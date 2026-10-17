/*
 * dosipas-c: table-driven ASN.1 UPER decoder producing a generic value tree.
 *
 * Decoding rules follow asn1-per-ts (the codec under dosipas-ts) exactly,
 * including its limits: no fragmented length determinants, extension
 * additions skipped by length, extension indices out of range are errors.
 *
 * Every read is bounds-checked against the current view (`ds_bits_t.end`),
 * every length is checked against the bits left before it is used, and every
 * allocation goes through the caller's arena. Recursion depth is capped at
 * DOSIPAS_MAX_DEPTH and each frame is small (no local arrays).
 *
 * SPDX-License-Identifier: MIT
 */
#include "dosipas_internal.h"

/* ------------------------------------------------------------------------- */
/* Arena                                                                     */
/* ------------------------------------------------------------------------- */

void dosipas_arena_init(dosipas_arena_t *a, void *buffer, size_t size) {
    uintptr_t p = (uintptr_t)buffer;
    uintptr_t aligned = (p + 7u) & ~(uintptr_t)7u;
    a->base = (uint8_t *)aligned;
    a->cap = (size >= (aligned - p)) ? size - (aligned - p) : 0;
    a->used = 0;
    a->peak = 0;
    a->fail_code = DOSIPAS_OK;
    a->fail_bit = 0;
}

void dosipas_arena_reset(dosipas_arena_t *a) {
    a->used = 0;
    a->fail_code = DOSIPAS_OK;
    a->fail_bit = 0;
}

void *ds_arena_alloc(dosipas_arena_t *a, size_t n) {
    size_t rounded = (n + 7u) & ~(size_t)7u;
    if (rounded < n || rounded > a->cap - a->used) return NULL;
    void *p = a->base + a->used;
    a->used += rounded;
    if (a->used > a->peak) a->peak = a->used;
    memset(p, 0, rounded);
    return p;
}

void *dosipas_arena_alloc(dosipas_arena_t *a, size_t n) { return ds_arena_alloc(a, n); }

void ds_arena_trim(dosipas_arena_t *a, void *ptr, size_t old, size_t used) {
    size_t old_r = (old + 7u) & ~(size_t)7u;
    size_t used_r = (used + 7u) & ~(size_t)7u;
    if ((uint8_t *)ptr + old_r == a->base + a->used && used_r <= old_r) a->used -= old_r - used_r;
}

char *ds_arena_strdup(dosipas_arena_t *a, const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)ds_arena_alloc(a, n);
    if (p) memcpy(p, s, n);
    return p;
}

/* ------------------------------------------------------------------------- */
/* Decoder context                                                           */
/* ------------------------------------------------------------------------- */

typedef struct {
    ds_bits_t bits;
    dosipas_arena_t *arena;
    dosipas_err_t err;
    uint32_t err_bit;
    int depth;
} ds_ctx_t;

static bool fail(ds_ctx_t *c, dosipas_err_t err) {
    if (c->err == DOSIPAS_OK) {
        c->err = err;
        c->err_bit = c->bits.pos;
    }
    return false;
}

static bool read_bits(ds_ctx_t *c, unsigned n, uint32_t *out) {
    if (!ds_read_bits(&c->bits, n, out)) return fail(c, DOSIPAS_ERR_TRUNCATED);
    return true;
}

static dosipas_value_t *new_value(ds_ctx_t *c, uint8_t kind, uint16_t schema, uint16_t field) {
    dosipas_value_t *v = (dosipas_value_t *)ds_arena_alloc(c->arena, sizeof *v);
    if (!v) {
        fail(c, DOSIPAS_ERR_ARENA_FULL);
        return NULL;
    }
    v->kind = kind;
    v->schema = schema;
    v->field = field;
    v->bit_offset = c->bits.pos;
    return v;
}

/* Allocate n+1 bytes for string/octet content after checking that n bytes
 * (n*8 bits) are actually available, so a bogus length cannot exhaust the arena. */
static uint8_t *alloc_content(ds_ctx_t *c, uint32_t n, uint32_t bits_needed) {
    if (ds_bits_left(&c->bits) < bits_needed) {
        fail(c, DOSIPAS_ERR_LENGTH);
        return NULL;
    }
    uint8_t *p = (uint8_t *)ds_arena_alloc(c->arena, (size_t)n + 1u);
    if (!p) fail(c, DOSIPAS_ERR_ARENA_FULL);
    return p;
}

/* ------------------------------------------------------------------------- */
/* Length determinants (X.691 §10)                                           */
/* ------------------------------------------------------------------------- */

/* Unconstrained length: 0xxxxxxx | 10xxxxxx xxxxxxxx | 11xxxxxx (fragmented, unsupported). */
static bool len_unconstrained(ds_ctx_t *c, uint32_t *len) {
    uint32_t b;
    if (!read_bits(c, 1, &b)) return false;
    if (b == 0) return read_bits(c, 7, len);
    if (!read_bits(c, 1, &b)) return false;
    if (b == 0) return read_bits(c, 14, len);
    return fail(c, DOSIPAS_ERR_LENGTH);
}

/* Semi-constrained whole number with lower bound 0 (used by normally small numbers >= 64). */
static bool semi_constrained_u32(ds_ctx_t *c, uint32_t *out) {
    uint32_t len, v = 0, byte;
    if (!len_unconstrained(c, &len)) return false;
    if (len > 4) return fail(c, DOSIPAS_ERR_INTEGER);
    for (uint32_t i = 0; i < len; i++) {
        if (!read_bits(c, 8, &byte)) return false;
        v = (v << 8) | byte;
    }
    *out = v;
    return true;
}

/* Normally small non-negative whole number: 0 + 6 bits, or 1 + semi-constrained. */
static bool normally_small(ds_ctx_t *c, uint32_t *out) {
    uint32_t b;
    if (!read_bits(c, 1, &b)) return false;
    if (b == 0) return read_bits(c, 6, out);
    return semi_constrained_u32(c, out);
}

/* Length of a sized type (string, OCTET STRING, SEQUENCE OF) per its constraint. */
static bool len_sized(ds_ctx_t *c, const ds_node_t *n, uint32_t *len) {
    if (n->flags & DS_F_SIZE_FIXED) {
        if (n->flags & DS_F_EXTENSIBLE) {
            uint32_t ext;
            if (!read_bits(c, 1, &ext)) return false;
            if (ext) return len_unconstrained(c, len);
        }
        *len = (uint32_t)n->min;
        return true;
    }
    if (n->flags & DS_F_SIZE_RANGE) {
        if (n->flags & DS_F_EXTENSIBLE) {
            uint32_t ext;
            if (!read_bits(c, 1, &ext)) return false;
            if (ext) return len_unconstrained(c, len);
        }
        if (n->flags & DS_F_LEN_UNCONSTRAINED) return len_unconstrained(c, len);
        uint32_t v = 0;
        if (n->bits && !read_bits(c, n->bits, &v)) return false;
        *len = v + (uint32_t)n->min;
        return true;
    }
    return len_unconstrained(c, len);
}

/* ------------------------------------------------------------------------- */
/* Values                                                                    */
/* ------------------------------------------------------------------------- */

static dosipas_value_t *decode(ds_ctx_t *c, uint16_t node, uint16_t field);

static dosipas_value_t *decode_boolean(ds_ctx_t *c, uint16_t node, uint16_t field) {
    dosipas_value_t *v = new_value(c, DOSIPAS_V_BOOLEAN, node, field);
    uint32_t b;
    if (!v || !read_bits(c, 1, &b)) return NULL;
    v->u.i = b;
    v->bit_length = 1;
    return v;
}

static dosipas_value_t *decode_integer(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_INTEGER, node, field);
    if (!v) return NULL;
    if (n->flags & DS_F_RANGE) {
        uint32_t raw = 0;
        if (n->bits && !read_bits(c, n->bits, &raw)) return NULL;
        v->u.i = (int64_t)n->min + (int64_t)raw;
    } else {
        /* Unconstrained: length + two's complement big-endian bytes. */
        uint32_t len, byte;
        if (!len_unconstrained(c, &len)) return NULL;
        if (len > 8) {
            fail(c, DOSIPAS_ERR_INTEGER);
            return NULL;
        }
        if (ds_bits_left(&c->bits) < len * 8u) {
            fail(c, DOSIPAS_ERR_TRUNCATED);
            return NULL;
        }
        uint64_t acc = 0;
        for (uint32_t i = 0; i < len; i++) {
            if (!read_bits(c, 8, &byte)) return NULL;
            if (i == 0 && (byte & 0x80u)) acc = ~(uint64_t)0; /* sign-extend */
            acc = (acc << 8) | byte;
        }
        v->u.i = (int64_t)acc;
    }
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode_enumerated(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_ENUMERATED, node, field);
    uint32_t idx = 0, ext = 0;
    if (!v) return NULL;
    if ((n->flags & DS_F_EXTENSIBLE) && !read_bits(c, 1, &ext)) return NULL;
    if (ext) {
        if (!normally_small(c, &idx)) return NULL;
        if (idx >= n->ext_count) {
            fail(c, DOSIPAS_ERR_ENUM);
            return NULL;
        }
        idx += n->count;
    } else if (n->bits && !read_bits(c, n->bits, &idx)) {
        return NULL;
    }
    /* A root index past the last value cannot happen for a well-formed table
     * (bits = ceil(log2(count))) except when count is not a power of two. */
    if (idx >= (uint32_t)n->count + n->ext_count) {
        fail(c, DOSIPAS_ERR_ENUM);
        return NULL;
    }
    v->aux = (uint16_t)idx;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode_octets(ds_ctx_t *c, uint16_t node, uint16_t field, uint8_t kind) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, kind, node, field);
    uint32_t len;
    if (!v || !len_sized(c, n, &len)) return NULL;
    if (len > 0x0fffffffu) {
        fail(c, DOSIPAS_ERR_LENGTH);
        return NULL;
    }
    uint8_t *p = alloc_content(c, len, len * 8u);
    if (!p) return NULL;
    if (!ds_read_octets(&c->bits, p, len)) {
        fail(c, DOSIPAS_ERR_TRUNCATED);
        return NULL;
    }
    v->u.data.ptr = p;
    v->u.data.len = len;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode_ia5(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_STRING, node, field);
    uint32_t len;
    if (!v || !len_sized(c, n, &len)) return NULL;
    if (len > 0x0fffffffu) {
        fail(c, DOSIPAS_ERR_LENGTH);
        return NULL;
    }
    uint8_t *p = alloc_content(c, len, len * 7u);
    if (!p) return NULL;
    for (uint32_t i = 0; i < len; i++) {
        uint32_t ch;
        if (!read_bits(c, 7, &ch)) return NULL;
        p[i] = (uint8_t)ch;
    }
    v->u.data.ptr = p;
    v->u.data.len = len;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

/* Write a uint64 in decimal into buf (at least 21 bytes); returns the length. */
static unsigned u64_to_dec(uint64_t x, char *buf) {
    char tmp[21];
    unsigned n = 0;
    do {
        tmp[n++] = (char)('0' + (x % 10u));
        x /= 10u;
    } while (x);
    for (unsigned i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}

static dosipas_value_t *decode_oid(ds_ctx_t *c, uint16_t node, uint16_t field) {
    dosipas_value_t *v = new_value(c, DOSIPAS_V_OID, node, field);
    uint32_t len;
    if (!v || !len_unconstrained(c, &len)) return NULL;
    if (len == 0) {
        fail(c, DOSIPAS_ERR_OID);
        return NULL;
    }
    if (ds_bits_left(&c->bits) < len * 8u) {
        fail(c, DOSIPAS_ERR_LENGTH);
        return NULL;
    }
    /* Each content byte yields at most 3 digits plus a separator; the first
     * arc adds "2." at most. */
    size_t cap = (size_t)len * 4u + 4u;
    char *out = (char *)ds_arena_alloc(c->arena, cap);
    if (!out) {
        fail(c, DOSIPAS_ERR_ARENA_FULL);
        return NULL;
    }
    size_t w = 0;
    uint64_t arc = 0;
    unsigned arc_bytes = 0;
    bool first = true;
    for (uint32_t i = 0; i < len; i++) {
        uint32_t byte;
        if (!read_bits(c, 8, &byte)) return NULL;
        if (++arc_bytes > 9) { /* more than 63 bits */
            fail(c, DOSIPAS_ERR_OID);
            return NULL;
        }
        arc = (arc << 7) | (byte & 0x7fu);
        if (byte & 0x80u) continue;
        if (first) {
            uint64_t a0 = arc < 40 ? 0 : arc < 80 ? 1 : 2;
            uint64_t a1 = arc - a0 * 40;
            out[w++] = (char)('0' + a0);
            out[w++] = '.';
            w += u64_to_dec(a1, out + w);
            first = false;
        } else {
            out[w++] = '.';
            w += u64_to_dec(arc, out + w);
        }
        arc = 0;
        arc_bytes = 0;
    }
    if (arc_bytes != 0) { /* truncated base-128 arc */
        fail(c, DOSIPAS_ERR_OID);
        return NULL;
    }
    out[w] = '\0';
    ds_arena_trim(c->arena, out, cap, w + 1);
    v->u.data.ptr = (const uint8_t *)out;
    v->u.data.len = (uint32_t)w;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

/* Decode a value as an open type: an unconstrained byte length then the value
 * decoded inside those bytes. Known types are decoded, unknown ones skipped. */
static dosipas_value_t *decode_open_type(ds_ctx_t *c, uint16_t node, uint16_t field, bool known) {
    uint32_t blen;
    if (!len_unconstrained(c, &blen)) return NULL;
    if (blen > ds_bits_left(&c->bits) / 8u) {
        fail(c, DOSIPAS_ERR_LENGTH);
        return NULL;
    }
    uint32_t start = c->bits.pos, end = start + blen * 8u;
    dosipas_value_t *v = NULL;
    if (known) {
        uint32_t saved_end = c->bits.end;
        c->bits.end = end;
        v = decode(c, node, field);
        c->bits.end = saved_end;
        if (!v) return NULL;
        v->flags |= DOSIPAS_VF_EXTENSION;
    }
    c->bits.pos = end;
    return v;
}

static dosipas_value_t *make_default(ds_ctx_t *c, const ds_field_t *f, uint16_t field_idx) {
    const ds_node_t *n = &ds_nodes[f->node];
    int32_t d = ds_defaults[f->dflt];
    uint8_t kind;
    switch (n->kind) {
        case DS_K_INTEGER: kind = DOSIPAS_V_INTEGER; break;
        case DS_K_ENUMERATED: kind = DOSIPAS_V_ENUMERATED; break;
        case DS_K_BOOLEAN: kind = DOSIPAS_V_BOOLEAN; break;
        default: kind = DOSIPAS_V_STRING; break;
    }
    dosipas_value_t *v = new_value(c, kind, f->node, field_idx);
    if (!v) return NULL;
    v->flags = DOSIPAS_VF_DEFAULT;
    v->bit_length = 0;
    if (kind == DOSIPAS_V_ENUMERATED) {
        v->aux = (uint16_t)d;
    } else if (kind == DOSIPAS_V_STRING) {
        v->u.data.ptr = (const uint8_t *)DS_STR(d);
        v->u.data.len = (uint32_t)strlen(DS_STR(d));
    } else {
        v->u.i = d;
    }
    return v;
}

static void append(dosipas_value_t *parent, dosipas_value_t **tail, dosipas_value_t *child) {
    if (*tail) (*tail)->next = child;
    else parent->u.child = child;
    *tail = child;
    parent->aux++;
}

static dosipas_value_t *decode_sequence(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_SEQUENCE, node, field);
    dosipas_value_t *tail = NULL;
    uint32_t ext = 0, dummy;
    if (!v) return NULL;
    if ((n->flags & DS_F_EXTENSIBLE) && !read_bits(c, 1, &ext)) return NULL;

    /* Root preamble: one presence bit per OPTIONAL/DEFAULT root field. We keep
     * its position and look bits up as we go instead of storing a bitmap. */
    uint32_t preamble_pos = c->bits.pos;
    if (ds_bits_left(&c->bits) < n->preamble) {
        fail(c, DOSIPAS_ERR_TRUNCATED);
        return NULL;
    }
    c->bits.pos += n->preamble;

    uint32_t opt = 0;
    for (uint16_t i = 0; i < n->count; i++) {
        uint16_t fi = (uint16_t)(n->aux + i);
        const ds_field_t *f = &ds_fields[fi];
        dosipas_value_t *child;
        if (f->flags & (DS_FF_OPTIONAL | DS_FF_DEFAULT)) {
            bool present = ds_bit_at(c->bits.data, preamble_pos + opt) != 0;
            opt++;
            if (present) {
                child = decode(c, f->node, fi);
            } else if (f->flags & DS_FF_DEFAULT) {
                child = make_default(c, f, fi);
            } else {
                continue;
            }
        } else {
            child = decode(c, f->node, fi);
        }
        if (!child) return NULL;
        append(v, &tail, child);
    }

    if (ext) {
        uint32_t ext_count;
        if (!normally_small(c, &ext_count)) return NULL;
        ext_count += 1;
        uint32_t bitmap_pos = c->bits.pos;
        if (ds_bits_left(&c->bits) < ext_count) {
            fail(c, DOSIPAS_ERR_TRUNCATED);
            return NULL;
        }
        c->bits.pos += ext_count;
        for (uint32_t i = 0; i < ext_count; i++) {
            if (!ds_bit_at(c->bits.data, bitmap_pos + i)) continue;
            bool known = i < n->ext_count;
            uint16_t fi = known ? (uint16_t)(n->aux + n->count + i) : DOSIPAS_NO_FIELD;
            dosipas_value_t *child = decode_open_type(c, known ? ds_fields[fi].node : 0, fi, known);
            if (c->err) return NULL;
            if (child) append(v, &tail, child);
        }
    }
    (void)dummy;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode_sequence_of(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_SEQUENCE_OF, node, field);
    dosipas_value_t *tail = NULL;
    uint32_t count;
    if (!v || !len_sized(c, n, &count)) return NULL;
    for (uint32_t i = 0; i < count; i++) {
        dosipas_value_t *item = decode(c, n->aux, DOSIPAS_NO_FIELD);
        if (!item) return NULL;
        append(v, &tail, item);
    }
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode_choice(ds_ctx_t *c, uint16_t node, uint16_t field) {
    const ds_node_t *n = &ds_nodes[node];
    dosipas_value_t *v = new_value(c, DOSIPAS_V_CHOICE, node, field);
    uint32_t ext = 0, idx = 0;
    dosipas_value_t *child;
    if (!v) return NULL;
    if ((n->flags & DS_F_EXTENSIBLE) && !read_bits(c, 1, &ext)) return NULL;
    if (ext) {
        if (!normally_small(c, &idx)) return NULL;
        if (idx >= n->ext_count) {
            fail(c, DOSIPAS_ERR_CHOICE);
            return NULL;
        }
        idx += n->count;
        v->aux = (uint16_t)idx;
        child = decode_open_type(c, ds_alts[n->aux + idx].node, DOSIPAS_NO_FIELD, true);
    } else {
        if (n->bits && !read_bits(c, n->bits, &idx)) return NULL;
        if (idx >= n->count) {
            fail(c, DOSIPAS_ERR_CHOICE);
            return NULL;
        }
        v->aux = (uint16_t)idx;
        child = decode(c, ds_alts[n->aux + idx].node, DOSIPAS_NO_FIELD);
    }
    if (!child) return NULL;
    v->u.child = child;
    v->bit_length = c->bits.pos - v->bit_offset;
    return v;
}

static dosipas_value_t *decode(ds_ctx_t *c, uint16_t node, uint16_t field) {
    dosipas_value_t *v;
    if (c->err) return NULL;
    if (++c->depth > DOSIPAS_MAX_DEPTH) {
        fail(c, DOSIPAS_ERR_DEPTH);
        c->depth--;
        return NULL;
    }
    switch (ds_nodes[node].kind) {
        case DS_K_BOOLEAN: v = decode_boolean(c, node, field); break;
        case DS_K_INTEGER: v = decode_integer(c, node, field); break;
        case DS_K_ENUMERATED: v = decode_enumerated(c, node, field); break;
        case DS_K_OCTET_STRING: v = decode_octets(c, node, field, DOSIPAS_V_BYTES); break;
        case DS_K_UTF8STRING: v = decode_octets(c, node, field, DOSIPAS_V_STRING); break;
        case DS_K_OBJECT_IDENTIFIER: v = decode_oid(c, node, field); break;
        case DS_K_IA5STRING: v = decode_ia5(c, node, field); break;
        case DS_K_CHOICE: v = decode_choice(c, node, field); break;
        case DS_K_SEQUENCE: v = decode_sequence(c, node, field); break;
        case DS_K_SEQUENCE_OF: v = decode_sequence_of(c, node, field); break;
        default:
            fail(c, DOSIPAS_ERR_ARG);
            v = NULL;
            break;
    }
    c->depth--;
    return v;
}

dosipas_value_t *ds_decode_root(ds_bits_t *bits, uint16_t root, dosipas_arena_t *arena, dosipas_err_t *err,
                                uint32_t *fail_bit) {
    ds_ctx_t c;
    c.bits = *bits;
    c.arena = arena;
    c.err = DOSIPAS_OK;
    c.err_bit = 0;
    c.depth = 0;
    dosipas_value_t *v = decode(&c, root, DOSIPAS_NO_FIELD);
    *bits = c.bits;
    if (!v) {
        if (c.err == DOSIPAS_OK) c.err = DOSIPAS_ERR_ARG;
        *err = c.err;
        *fail_bit = c.err_bit;
        return NULL;
    }
    *err = DOSIPAS_OK;
    *fail_bit = 0;
    return v;
}

dosipas_err_t dosipas_decode_value(const uint8_t *data, size_t len, uint16_t root, dosipas_arena_t *arena,
                                   dosipas_value_t **out, uint32_t *fail_bit) {
    uint32_t fb = 0;
    dosipas_err_t err;
    if (out) *out = NULL;
    if (fail_bit) *fail_bit = 0;
    if (!data || !arena || !out || len == 0 || len > (0xffffffffu / 8u) || root >= DS_NODE_COUNT)
        return DOSIPAS_ERR_ARG;
    ds_bits_t bits = {data, 0, (uint32_t)len * 8u};
    dosipas_value_t *v = ds_decode_root(&bits, root, arena, &err, &fb);
    if (fail_bit) *fail_bit = fb;
    if (!v) return err;
    *out = v;
    return DOSIPAS_OK;
}

/* ------------------------------------------------------------------------- */
/* Value accessors                                                           */
/* ------------------------------------------------------------------------- */

const char *dosipas_value_name(const dosipas_value_t *v) {
    if (!v || v->field == DOSIPAS_NO_FIELD || v->field >= DS_FIELD_COUNT) return NULL;
    return DS_STR(ds_fields[v->field].name);
}

const dosipas_value_t *ds_member(const dosipas_value_t *seq, uint16_t name_off) {
    if (!seq || seq->kind != DOSIPAS_V_SEQUENCE) return NULL;
    for (const dosipas_value_t *m = seq->u.child; m; m = m->next) {
        if (m->field != DOSIPAS_NO_FIELD && ds_fields[m->field].name == name_off) return m;
    }
    return NULL;
}

const dosipas_value_t *dosipas_value_field(const dosipas_value_t *seq, const char *name) {
    if (!seq || !name || seq->kind != DOSIPAS_V_SEQUENCE) return NULL;
    for (const dosipas_value_t *m = seq->u.child; m; m = m->next) {
        const char *n = dosipas_value_name(m);
        if (n && strcmp(n, name) == 0) return m;
    }
    return NULL;
}

const dosipas_value_t *dosipas_value_item(const dosipas_value_t *list, size_t index) {
    if (!list || list->kind != DOSIPAS_V_SEQUENCE_OF) return NULL;
    const dosipas_value_t *m = list->u.child;
    while (m && index--) m = m->next;
    return m;
}

const char *dosipas_value_enum_name(const dosipas_value_t *v) {
    if (!v || v->kind != DOSIPAS_V_ENUMERATED || v->schema >= DS_NODE_COUNT) return NULL;
    const ds_node_t *n = &ds_nodes[v->schema];
    if (v->aux >= (uint32_t)n->count + n->ext_count) return NULL;
    return DS_STR(ds_enum_names[n->aux + v->aux]);
}

const char *dosipas_value_choice_key(const dosipas_value_t *v) {
    if (!v || v->kind != DOSIPAS_V_CHOICE || v->schema >= DS_NODE_COUNT) return NULL;
    const ds_node_t *n = &ds_nodes[v->schema];
    if (v->aux >= (uint32_t)n->count + n->ext_count) return NULL;
    return DS_STR(ds_alts[n->aux + v->aux].name);
}

/* ------------------------------------------------------------------------- */
/* Misc                                                                      */
/* ------------------------------------------------------------------------- */

const char *dosipas_strerror(dosipas_err_t err) {
    switch (err) {
        case DOSIPAS_OK: return "ok";
        case DOSIPAS_ERR_ARG: return "invalid argument";
        case DOSIPAS_ERR_TRUNCATED: return "payload truncated";
        case DOSIPAS_ERR_ARENA_FULL: return "arena full";
        case DOSIPAS_ERR_DEPTH: return "nesting too deep";
        case DOSIPAS_ERR_LENGTH: return "bad length determinant";
        case DOSIPAS_ERR_INTEGER: return "integer too wide";
        case DOSIPAS_ERR_ENUM: return "enumeration index out of range";
        case DOSIPAS_ERR_CHOICE: return "choice index out of range";
        case DOSIPAS_ERR_OID: return "malformed object identifier";
        case DOSIPAS_ERR_FORMAT: return "unknown header format";
        case DOSIPAS_ERR_HEADER_VERSION: return "unsupported header version";
        case DOSIPAS_ERR_SMALL_BUFFER: return "output buffer too small";
        case DOSIPAS_ERR_UNSUPPORTED: return "unsupported";
        default: return "unknown error";
    }
}

bool ds_is_intercode_issuing_extension(const char *id) {
    /* ^[_+](\d+|[A-Z]{2})II1$ */
    if (!id || (id[0] != '_' && id[0] != '+')) return false;
    const char *p = id + 1;
    if (p[0] >= '0' && p[0] <= '9') {
        while (*p >= '0' && *p <= '9') p++;
    } else if (p[0] >= 'A' && p[0] <= 'Z' && p[1] >= 'A' && p[1] <= 'Z') {
        p += 2;
    } else {
        return false;
    }
    return strcmp(p, "II1") == 0;
}

bool ds_is_intercode_dynamic_format(const char *fmt) {
    /* ^_\d+\.ID1$ */
    if (!fmt || fmt[0] != '_') return false;
    const char *p = fmt + 1;
    if (!(*p >= '0' && *p <= '9')) return false;
    while (*p >= '0' && *p <= '9') p++;
    return strcmp(p, ".ID1") == 0;
}

long ds_match_versioned(const char *s, const char *prefix) {
    size_t pl = strlen(prefix);
    if (!s || strncmp(s, prefix, pl) != 0) return -1;
    const char *p = s + pl;
    if (!(*p >= '0' && *p <= '9')) return -1;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        if (v < 1000000) v = v * 10 + (*p - '0');
        p++;
    }
    return *p == '\0' ? v : -1;
}
