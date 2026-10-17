/*
 * dosipas-c internals shared between the decoder, the ticket binder and the
 * JSON writer. Not part of the public API.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_INTERNAL_H
#define DOSIPAS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dosipas.h"
#include "dosipas_schema.h"
#include "dosipas_schema_names.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bit reader over a byte buffer. Positions are absolute bit offsets into
 * `data`; `end` bounds the current (open type) view. */
typedef struct {
    const uint8_t *data;
    uint32_t pos;
    uint32_t end;
} ds_bits_t;

static inline uint32_t ds_bits_left(const ds_bits_t *b) { return b->end - b->pos; }

static inline uint32_t ds_bit_at(const uint8_t *data, uint32_t pos) {
    return (uint32_t)(data[pos >> 3] >> (7 - (pos & 7))) & 1u;
}

/* Read n <= 32 bits MSB first. Returns false when fewer than n bits are left. */
static inline bool ds_read_bits(ds_bits_t *b, unsigned n, uint32_t *out) {
    uint32_t v = 0;
    if (ds_bits_left(b) < n) return false;
    while (n--) {
        v = (v << 1) | ds_bit_at(b->data, b->pos);
        b->pos++;
    }
    *out = v;
    return true;
}

/* Copy n bytes starting at the current bit position (any alignment) into out. */
static inline bool ds_read_octets(ds_bits_t *b, uint8_t *out, uint32_t n) {
    if (ds_bits_left(b) < n * 8u) return false;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t byte_i = b->pos >> 3, shift = b->pos & 7;
        uint32_t v = (uint32_t)b->data[byte_i] << 8;
        if (shift) v |= b->data[byte_i + 1];
        out[i] = (uint8_t)(v >> (8 - shift));
        b->pos += 8;
    }
    return true;
}

/* Arena helpers. */
void *ds_arena_alloc(dosipas_arena_t *a, size_t n);
/* Give back the tail of the most recent allocation: `ptr` was allocated with
 * `old` bytes, only `used` are needed. */
void ds_arena_trim(dosipas_arena_t *a, void *ptr, size_t old, size_t used);
char *ds_arena_strdup(dosipas_arena_t *a, const char *s);

/* Generic decoder entry: decode schema node `root` from `bits`. On error
 * returns NULL and sets *err / *fail_bit. */
dosipas_value_t *ds_decode_root(ds_bits_t *bits, uint16_t root, dosipas_arena_t *arena, dosipas_err_t *err,
                                uint32_t *fail_bit);

/* Member lookup by string-pool offset (DS_NAME_*). */
const dosipas_value_t *ds_member(const dosipas_value_t *seq, uint16_t name_off);

/* Simple pattern checks mirroring the dosipas-ts regular expressions. */
bool ds_is_intercode_issuing_extension(const char *id); /* ^[_+](\d+|[A-Z]{2})II1$ */
bool ds_is_intercode_dynamic_format(const char *fmt);   /* ^_\d+\.ID1$ */
/* ^<prefix>(\d+)$ -> version (parseInt, clamped to 1000000 on overflow), -1 when no match */
long ds_match_versioned(const char *s, const char *prefix);

#ifdef __cplusplus
}
#endif

#endif /* DOSIPAS_INTERNAL_H */
