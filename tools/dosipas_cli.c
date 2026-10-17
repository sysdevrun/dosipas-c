/*
 * Host command-line decoder: prints the JSON for a hex payload.
 *
 *   dosipas_cli <hex>            decode one payload given on the command line
 *   dosipas_cli -f <file.hex>    decode a payload from a hex text file
 *   dosipas_cli -b <file.bin>    decode a binary payload file
 *
 * Also prints arena usage and the signed byte ranges on stderr.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dosipas.h"
#include "dosipas_json.h"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    int hi = -1;
    for (; *s; s++) {
        int v = hexval(*s);
        if (v < 0) continue;
        if (hi < 0) {
            hi = v;
        } else {
            if (n < cap) out[n] = (uint8_t)(hi * 16 + v);
            n++;
            hi = -1;
        }
    }
    return n;
}

int main(int argc, char **argv) {
    static uint8_t payload[8192];
    static uint8_t arena_buf[64 * 1024];
    static char json[64 * 1024];
    size_t len = 0;

    if (argc == 3 && strcmp(argv[1], "-f") == 0) {
        FILE *f = fopen(argv[2], "rb");
        static char text[32768];
        if (!f) { perror(argv[2]); return 2; }
        size_t n = fread(text, 1, sizeof text - 1, f);
        fclose(f);
        text[n] = 0;
        len = parse_hex(text, payload, sizeof payload);
    } else if (argc == 3 && strcmp(argv[1], "-b") == 0) {
        FILE *f = fopen(argv[2], "rb");
        if (!f) { perror(argv[2]); return 2; }
        len = fread(payload, 1, sizeof payload, f);
        fclose(f);
    } else if (argc == 2) {
        len = parse_hex(argv[1], payload, sizeof payload);
    } else {
        fprintf(stderr, "usage: %s <hex> | -f <file.hex> | -b <file.bin>\n", argv[0]);
        return 2;
    }
    if (len == 0 || len > sizeof payload) {
        fprintf(stderr, "bad payload length %zu\n", len);
        return 2;
    }

    dosipas_arena_t arena;
    dosipas_arena_init(&arena, arena_buf, sizeof arena_buf);
    dosipas_ticket_t *t = NULL;
    dosipas_err_t err = dosipas_decode(payload, len, &arena, &t);
    if (err != DOSIPAS_OK) {
        fprintf(stderr, "decode failed: %s (code %d) at bit %u\n", dosipas_strerror(err), (int)err, arena.fail_bit);
        return 1;
    }
    size_t needed = 0;
    err = dosipas_json_write(t, json, sizeof json, &needed);
    if (err != DOSIPAS_OK) {
        fprintf(stderr, "json failed: %s (needed %zu)\n", dosipas_strerror(err), needed);
        return 1;
    }
    puts(json);
    fprintf(stderr, "payload %zu B, arena peak %zu B, level1Data bits [%u,+%u), level2SignedData bits [%u,+%u)\n", len,
            arena.peak, t->level1Data.bit_offset, t->level1Data.bit_length, t->level2SignedData_bit_offset,
            t->level2SignedData_bit_length);
    for (size_t i = 0; i < t->level1Data.dataSequence_count; i++) {
        const dosipas_data_entry_t *e = &t->level1Data.dataSequence[i];
        if (!e->decoded && e->decode_error)
            fprintf(stderr, "dataSequence[%zu] %s: not decoded: %s at bit %u\n", i, e->dataFormat,
                    dosipas_strerror(e->decode_error), e->decode_error_bit);
    }
    if (t->level2Data && t->level2Data->decode_error)
        fprintf(stderr, "level2Data %s: not decoded: %s at bit %u\n", t->level2Data->dataFormat,
                dosipas_strerror(t->level2Data->decode_error), t->level2Data->decode_error_bit);
    return 0;
}
