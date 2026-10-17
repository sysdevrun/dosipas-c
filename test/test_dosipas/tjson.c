/* SPDX-License-Identifier: MIT */
#include "tjson.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p, *end;
    bool err;
} P;

static void ws(P *p) {
    while (p->p < p->end && (*p->p == ' ' || *p->p == '\n' || *p->p == '\r' || *p->p == '\t')) p->p++;
}

static tj_value_t *node(tj_kind_t k) {
    tj_value_t *v = (tj_value_t *)calloc(1, sizeof *v);
    if (v) v->kind = k;
    return v;
}

static tj_value_t *parse_value(P *p, int depth);

static char *parse_string_raw(P *p) {
    /* p->p points after the opening quote. Unescapes into a malloc'd buffer. */
    size_t cap = 32, n = 0;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    while (p->p < p->end && *p->p != '"') {
        unsigned c = (unsigned char)*p->p++;
        if (c == '\\') {
            if (p->p >= p->end) goto fail;
            c = (unsigned char)*p->p++;
            switch (c) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case '/': case '\\': case '"': break;
                case 'u': {
                    if (p->end - p->p < 4) goto fail;
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = *p->p++;
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                        else goto fail;
                    }
                    /* Surrogate pairs. */
                    if (cp >= 0xd800 && cp < 0xdc00 && p->end - p->p >= 6 && p->p[0] == '\\' && p->p[1] == 'u') {
                        unsigned lo = 0;
                        for (int i = 0; i < 4; i++) {
                            char h = p->p[2 + i];
                            lo <<= 4;
                            if (h >= '0' && h <= '9') lo |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') lo |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') lo |= (unsigned)(h - 'A' + 10);
                        }
                        if (lo >= 0xdc00 && lo < 0xe000) {
                            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            p->p += 6;
                        }
                    }
                    /* UTF-8 encode. */
                    char buf[4];
                    int bl;
                    if (cp < 0x80) { buf[0] = (char)cp; bl = 1; }
                    else if (cp < 0x800) { buf[0] = (char)(0xc0 | (cp >> 6)); buf[1] = (char)(0x80 | (cp & 0x3f)); bl = 2; }
                    else if (cp < 0x10000) { buf[0] = (char)(0xe0 | (cp >> 12)); buf[1] = (char)(0x80 | ((cp >> 6) & 0x3f)); buf[2] = (char)(0x80 | (cp & 0x3f)); bl = 3; }
                    else { buf[0] = (char)(0xf0 | (cp >> 18)); buf[1] = (char)(0x80 | ((cp >> 12) & 0x3f)); buf[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); buf[3] = (char)(0x80 | (cp & 0x3f)); bl = 4; }
                    for (int i = 0; i < bl; i++) {
                        if (n + 1 >= cap) { cap *= 2; char *nb = (char *)realloc(out, cap); if (!nb) goto fail; out = nb; }
                        out[n++] = buf[i];
                    }
                    continue;
                }
                default: goto fail;
            }
        }
        if (n + 1 >= cap) {
            cap *= 2;
            char *nb = (char *)realloc(out, cap);
            if (!nb) goto fail;
            out = nb;
        }
        out[n++] = (char)c;
    }
    if (p->p >= p->end) goto fail;
    p->p++; /* closing quote */
    out[n] = '\0';
    return out;
fail:
    free(out);
    p->err = true;
    return NULL;
}

static tj_value_t *parse_value(P *p, int depth) {
    ws(p);
    if (p->p >= p->end || depth > 64) {
        p->err = true;
        return NULL;
    }
    char c = *p->p;
    if (c == '{' || c == '[') {
        bool obj = c == '{';
        tj_value_t *v = node(obj ? TJ_OBJECT : TJ_ARRAY);
        tj_value_t *tail = NULL;
        p->p++;
        ws(p);
        if (p->p < p->end && *p->p == (obj ? '}' : ']')) {
            p->p++;
            return v;
        }
        for (;;) {
            char *key = NULL;
            if (obj) {
                ws(p);
                if (p->p >= p->end || *p->p != '"') goto fail;
                p->p++;
                key = parse_string_raw(p);
                if (!key) goto fail;
                ws(p);
                if (p->p >= p->end || *p->p != ':') { free(key); goto fail; }
                p->p++;
            }
            tj_value_t *item = parse_value(p, depth + 1);
            if (!item) { free(key); goto fail; }
            item->key = key;
            if (tail) tail->next = item; else v->child = item;
            tail = item;
            v->count++;
            ws(p);
            if (p->p >= p->end) goto fail;
            if (*p->p == ',') { p->p++; continue; }
            if (*p->p == (obj ? '}' : ']')) { p->p++; return v; }
            goto fail;
        }
    fail:
        p->err = true;
        tj_free(v);
        return NULL;
    }
    if (c == '"') {
        p->p++;
        char *s = parse_string_raw(p);
        if (!s) return NULL;
        tj_value_t *v = node(TJ_STRING);
        v->str = s;
        return v;
    }
    if (c == 't' && p->end - p->p >= 4 && strncmp(p->p, "true", 4) == 0) { p->p += 4; tj_value_t *v = node(TJ_BOOL); v->b = true; return v; }
    if (c == 'f' && p->end - p->p >= 5 && strncmp(p->p, "false", 5) == 0) { p->p += 5; return node(TJ_BOOL); }
    if (c == 'n' && p->end - p->p >= 4 && strncmp(p->p, "null", 4) == 0) { p->p += 4; return node(TJ_NULL); }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *start = p->p;
        bool is_int = true;
        if (*p->p == '-') p->p++;
        while (p->p < p->end && ((*p->p >= '0' && *p->p <= '9') || *p->p == '.' || *p->p == 'e' || *p->p == 'E' || *p->p == '+' || *p->p == '-')) {
            if (*p->p == '.' || *p->p == 'e' || *p->p == 'E') is_int = false;
            p->p++;
        }
        char buf[64];
        size_t n = (size_t)(p->p - start);
        if (n >= sizeof buf) { p->err = true; return NULL; }
        memcpy(buf, start, n);
        buf[n] = 0;
        tj_value_t *v = node(TJ_NUMBER);
        v->is_int = is_int;
        v->num = strtod(buf, NULL);
        if (is_int) v->inum = strtoll(buf, NULL, 10);
        return v;
    }
    p->err = true;
    return NULL;
}

tj_value_t *tj_parse(const char *text, size_t len) {
    P p = {text, text + len, false};
    tj_value_t *v = parse_value(&p, 0);
    if (!v) return NULL;
    ws(&p);
    if (p.p != p.end) {
        tj_free(v);
        return NULL;
    }
    return v;
}

void tj_free(tj_value_t *v) {
    while (v) {
        tj_value_t *next = v->next;
        tj_free(v->child);
        free((void *)v->str);
        free((void *)v->key);
        free(v);
        v = next;
    }
}

const tj_value_t *tj_get(const tj_value_t *obj, const char *key) {
    if (!obj || obj->kind != TJ_OBJECT) return NULL;
    for (const tj_value_t *m = obj->child; m; m = m->next)
        if (m->key && strcmp(m->key, key) == 0) return m;
    return NULL;
}

const tj_value_t *tj_at(const tj_value_t *arr, size_t i) {
    if (!arr || arr->kind != TJ_ARRAY) return NULL;
    const tj_value_t *m = arr->child;
    while (m && i--) m = m->next;
    return m;
}

static const char *kind_name(tj_kind_t k) {
    static const char *names[] = {"null", "bool", "number", "string", "array", "object"};
    return names[k];
}

static bool eq(const tj_value_t *e, const tj_value_t *a, char *path, size_t plen, size_t pcap, char *diff, size_t cap) {
    if (e->kind != a->kind) {
        snprintf(diff, cap, "%s: expected %s, got %s", path, kind_name(e->kind), kind_name(a->kind));
        return false;
    }
    switch (e->kind) {
        case TJ_NULL: return true;
        case TJ_BOOL:
            if (e->b != a->b) { snprintf(diff, cap, "%s: expected %s, got %s", path, e->b ? "true" : "false", a->b ? "true" : "false"); return false; }
            return true;
        case TJ_NUMBER:
            if (e->is_int && a->is_int) {
                if (e->inum != a->inum) { snprintf(diff, cap, "%s: expected %lld, got %lld", path, (long long)e->inum, (long long)a->inum); return false; }
                return true;
            }
            if (e->num != a->num) { snprintf(diff, cap, "%s: expected %g, got %g", path, e->num, a->num); return false; }
            return true;
        case TJ_STRING:
            if (strcmp(e->str, a->str) != 0) { snprintf(diff, cap, "%s: expected \"%s\", got \"%s\"", path, e->str, a->str); return false; }
            return true;
        case TJ_ARRAY: {
            if (e->count != a->count) { snprintf(diff, cap, "%s: expected %u items, got %u", path, (unsigned)e->count, (unsigned)a->count); return false; }
            const tj_value_t *x = e->child, *y = a->child;
            for (size_t i = 0; x && y; i++, x = x->next, y = y->next) {
                int n = snprintf(path + plen, pcap - plen, "[%u]", (unsigned)i);
                if (!eq(x, y, path, plen + (size_t)n, pcap, diff, cap)) return false;
                path[plen] = 0;
            }
            return true;
        }
        case TJ_OBJECT: {
            for (const tj_value_t *m = e->child; m; m = m->next) {
                const tj_value_t *o = tj_get(a, m->key);
                if (!o) { snprintf(diff, cap, "%s.%s: missing in actual", path, m->key); return false; }
                int n = snprintf(path + plen, pcap - plen, ".%s", m->key);
                if (!eq(m, o, path, plen + (size_t)n, pcap, diff, cap)) return false;
                path[plen] = 0;
            }
            for (const tj_value_t *m = a->child; m; m = m->next) {
                if (!tj_get(e, m->key)) { snprintf(diff, cap, "%s.%s: unexpected in actual", path, m->key); return false; }
            }
            return true;
        }
    }
    return false;
}

bool tj_equal(const tj_value_t *expected, const tj_value_t *actual, char *diff, size_t cap) {
    char path[512] = "$";
    if (!expected || !actual) {
        snprintf(diff, cap, "null tree");
        return false;
    }
    return eq(expected, actual, path, 1, sizeof path, diff, cap);
}
