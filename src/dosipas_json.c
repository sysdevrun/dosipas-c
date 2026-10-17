/*
 * dosipas-c: JSON serializer (see dosipas_json.h).
 *
 * SPDX-License-Identifier: MIT
 */
#include "dosipas_internal.h"
#include "dosipas_json.h"

typedef struct {
    char *buf;
    size_t cap;
    size_t len; /* total length needed, may exceed cap */
} out_t;

static void put_c(out_t *o, char c) {
    if (o->len + 1 < o->cap) o->buf[o->len] = c;
    o->len++;
}

static void put_s(out_t *o, const char *s) {
    while (*s) put_c(o, *s++);
}

static void put_hex(out_t *o, const uint8_t *p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        put_c(o, digits[p[i] >> 4]);
        put_c(o, digits[p[i] & 15]);
    }
}

static void put_i64(out_t *o, int64_t v) {
    char tmp[21];
    unsigned n = 0;
    uint64_t u = v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
    if (v < 0) put_c(o, '-');
    do {
        tmp[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u);
    while (n) put_c(o, tmp[--n]);
}

/* JSON string: bytes are copied unchanged (UTF-8 passthrough), only the
 * characters JSON requires are escaped. */
static void put_str(out_t *o, const uint8_t *s, size_t n) {
    static const char digits[] = "0123456789abcdef";
    put_c(o, '"');
    for (size_t i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c == '"' || c == '\\') {
            put_c(o, '\\');
            put_c(o, (char)c);
        } else if (c < 0x20) {
            put_s(o, "\\u00");
            put_c(o, digits[c >> 4]);
            put_c(o, digits[c & 15]);
        } else {
            put_c(o, (char)c);
        }
    }
    put_c(o, '"');
}

static void put_key(out_t *o, const char *name, bool *first) {
    if (!*first) put_c(o, ',');
    *first = false;
    put_str(o, (const uint8_t *)name, strlen(name));
    put_c(o, ':');
}

/* ------------------------------------------------------------------------- */
/* Generic values                                                            */
/* ------------------------------------------------------------------------- */

static void write_value(out_t *o, const dosipas_value_t *v, int depth);

static void write_members(out_t *o, const dosipas_value_t *seq, int depth) {
    bool first = true;
    for (const dosipas_value_t *m = seq->u.child; m; m = m->next) {
        const char *name = dosipas_value_name(m);
        put_key(o, name ? name : "?", &first);
        write_value(o, m, depth);
    }
}

static void write_value(out_t *o, const dosipas_value_t *v, int depth) {
    if (!v || depth > DOSIPAS_MAX_DEPTH + 2) {
        put_s(o, "null");
        return;
    }
    switch (v->kind) {
        case DOSIPAS_V_BOOLEAN: put_s(o, v->u.i ? "true" : "false"); break;
        case DOSIPAS_V_INTEGER: put_i64(o, v->u.i); break;
        case DOSIPAS_V_ENUMERATED: {
            const char *n = dosipas_value_enum_name(v);
            if (n) put_str(o, (const uint8_t *)n, strlen(n));
            else put_s(o, "null");
            break;
        }
        case DOSIPAS_V_BYTES:
            put_c(o, '"');
            put_hex(o, v->u.data.ptr, v->u.data.len);
            put_c(o, '"');
            break;
        case DOSIPAS_V_OID:
        case DOSIPAS_V_STRING: put_str(o, v->u.data.ptr, v->u.data.len); break;
        case DOSIPAS_V_CHOICE: {
            const char *k = dosipas_value_choice_key(v);
            put_s(o, "{\"key\":");
            put_str(o, (const uint8_t *)(k ? k : "?"), strlen(k ? k : "?"));
            put_s(o, ",\"value\":");
            write_value(o, v->u.child, depth + 1);
            put_c(o, '}');
            break;
        }
        case DOSIPAS_V_SEQUENCE:
            put_c(o, '{');
            write_members(o, v, depth + 1);
            put_c(o, '}');
            break;
        case DOSIPAS_V_SEQUENCE_OF: {
            bool first = true;
            put_c(o, '[');
            for (const dosipas_value_t *m = v->u.child; m; m = m->next) {
                if (!first) put_c(o, ',');
                first = false;
                write_value(o, m, depth + 1);
            }
            put_c(o, ']');
            break;
        }
        default: put_s(o, "null"); break;
    }
}

/* ------------------------------------------------------------------------- */
/* Ticket with the dosipas-ts additions                                      */
/* ------------------------------------------------------------------------- */

/* issuingDetail: the schema members, plus `intercodeIssuing` (decoded
 * extension with its `extensionId`) exactly as decoder.ts adds it. */
static void write_issuing(out_t *o, const dosipas_issuing_detail_t *iss) {
    put_c(o, '{');
    write_members(o, iss->value, 2);
    if (iss->intercodeIssuing && iss->intercodeIssuing->value) {
        bool first = iss->value->u.child == NULL;
        put_key(o, "intercodeIssuing", &first);
        put_c(o, '{');
        bool f2 = true;
        for (const dosipas_value_t *m = iss->intercodeIssuing->value->u.child; m; m = m->next) {
            const char *name = dosipas_value_name(m);
            put_key(o, name ? name : "?", &f2);
            write_value(o, m, 3);
        }
        put_key(o, "extensionId", &f2);
        const char *id = iss->intercodeIssuing->extensionId ? iss->intercodeIssuing->extensionId : "";
        put_str(o, (const uint8_t *)id, strlen(id));
        put_c(o, '}');
    }
    put_c(o, '}');
}

static void write_rail_ticket(out_t *o, const dosipas_rail_ticket_t *rt) {
    bool first = true;
    put_c(o, '{');
    for (const dosipas_value_t *m = rt->value->u.child; m; m = m->next) {
        const char *name = dosipas_value_name(m);
        put_key(o, name ? name : "?", &first);
        if (m->field != DOSIPAS_NO_FIELD && ds_fields[m->field].name == DS_NAME_issuingDetail && rt->issuingDetail &&
            rt->issuingDetail->value == m) {
            write_issuing(o, rt->issuingDetail);
        } else {
            write_value(o, m, 2);
        }
    }
    put_c(o, '}');
}

static void write_data_entry(out_t *o, const dosipas_value_t *entry, const dosipas_data_entry_t *typed) {
    put_c(o, '{');
    write_members(o, entry, 3);
    if (typed && typed->decoded) {
        put_s(o, ",\"decoded\":");
        write_rail_ticket(o, typed->decoded);
    }
    put_c(o, '}');
}

static void write_level2_data(out_t *o, const dosipas_value_t *entry, const dosipas_level2_data_t *typed) {
    put_c(o, '{');
    write_members(o, entry, 3);
    if (typed) {
        const dosipas_value_t *decoded = typed->fdc1 ? typed->fdc1->value : typed->intercode ? typed->intercode->value : NULL;
        if (decoded) {
            put_s(o, ",\"decoded\":");
            write_value(o, decoded, 3);
        }
    }
    put_c(o, '}');
}

static void write_level1(out_t *o, const dosipas_value_t *l1, const dosipas_ticket_t *t) {
    bool first = true;
    put_c(o, '{');
    for (const dosipas_value_t *m = l1->u.child; m; m = m->next) {
        const char *name = dosipas_value_name(m);
        put_key(o, name ? name : "?", &first);
        if (m->field != DOSIPAS_NO_FIELD && ds_fields[m->field].name == DS_NAME_dataSequence &&
            m->kind == DOSIPAS_V_SEQUENCE_OF) {
            size_t i = 0;
            put_c(o, '[');
            for (const dosipas_value_t *e = m->u.child; e; e = e->next, i++) {
                if (i) put_c(o, ',');
                write_data_entry(o, e, i < t->level1Data.dataSequence_count ? &t->level1Data.dataSequence[i] : NULL);
            }
            put_c(o, ']');
        } else {
            write_value(o, m, 2);
        }
    }
    put_c(o, '}');
}

static void write_ticket(out_t *o, const dosipas_ticket_t *t) {
    bool first = true;
    put_c(o, '{');
    for (const dosipas_value_t *m = t->header->u.child; m; m = m->next) {
        const char *name = dosipas_value_name(m);
        put_key(o, name ? name : "?", &first);
        if (m->field != DOSIPAS_NO_FIELD && ds_fields[m->field].name == DS_NAME_level2SignedData &&
            m->kind == DOSIPAS_V_SEQUENCE) {
            bool f2 = true;
            put_c(o, '{');
            for (const dosipas_value_t *s = m->u.child; s; s = s->next) {
                const char *sname = dosipas_value_name(s);
                put_key(o, sname ? sname : "?", &f2);
                uint16_t off = s->field != DOSIPAS_NO_FIELD ? ds_fields[s->field].name : 0xffffu;
                if (off == DS_NAME_level1Data && s->kind == DOSIPAS_V_SEQUENCE) write_level1(o, s, t);
                else if (off == DS_NAME_level2Data && s->kind == DOSIPAS_V_SEQUENCE) write_level2_data(o, s, t->level2Data);
                else write_value(o, s, 2);
            }
            put_c(o, '}');
        } else {
            write_value(o, m, 1);
        }
    }
    put_c(o, '}');
}

static dosipas_err_t finish(out_t *o, size_t *needed) {
    if (o->cap) o->buf[o->len < o->cap ? o->len : o->cap - 1] = '\0';
    if (needed) *needed = o->len;
    return o->len + 1 <= o->cap ? DOSIPAS_OK : DOSIPAS_ERR_SMALL_BUFFER;
}

dosipas_err_t dosipas_json_write(const dosipas_ticket_t *t, char *buf, size_t cap, size_t *needed) {
    out_t o = {buf, buf ? cap : 0, 0};
    if (!t || !t->header) return DOSIPAS_ERR_ARG;
    write_ticket(&o, t);
    return finish(&o, needed);
}

dosipas_err_t dosipas_json_write_value(const dosipas_value_t *v, char *buf, size_t cap, size_t *needed) {
    out_t o = {buf, buf ? cap : 0, 0};
    if (!v) return DOSIPAS_ERR_ARG;
    write_value(&o, v, 0);
    return finish(&o, needed);
}
