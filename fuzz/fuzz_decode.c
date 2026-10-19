/*
 * libFuzzer target for the dosipas-c decoder entry point.
 *
 * Build and run (macOS needs Homebrew LLVM, Apple clang has no libFuzzer):
 *   fuzz/run.sh [seconds]
 *
 * Every input goes through dosipas_decode(); on success the JSON writer, the
 * time helpers, the summary and the signed-byte extraction run too, so the
 * whole read-side API is exercised on hostile data.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dosipas.h"
#include "dosipas_json.h"
#include "dosipas_summary.h"

static uint8_t arena_buf[DOSIPAS_RECOMMENDED_ARENA_SIZE];
static char json[8192];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    dosipas_arena_t arena;
    dosipas_ticket_t *t = NULL;
    /* Vary the arena size with the input so arena exhaustion paths get fuzzed too. */
    size_t cap = size ? 512 + (size_t)data[size - 1] * 64 : sizeof arena_buf;
    if (cap > sizeof arena_buf) cap = sizeof arena_buf;
    dosipas_arena_init(&arena, arena_buf, cap);
    static int once;
    if (!once) { /* argument checks, once */
        once = 1;
        dosipas_ticket_t *o;
        size_t k;
        int64_t x;
        (void)dosipas_decode(NULL, 1, &arena, &o);
        (void)dosipas_decode(data, size, NULL, NULL);
        (void)dosipas_json_write(NULL, json, sizeof json, &k);
        (void)dosipas_json_write_value(NULL, json, sizeof json, &k);
        (void)dosipas_extract_bits(NULL, 0, 0, 0, NULL, 0, &k);
        (void)dosipas_extract_bits(data, size, 0, 8, NULL, 0, &k);
        (void)dosipas_level1_signed_bytes(data, size, NULL, NULL, 0, &k);
        (void)dosipas_level2_signed_bytes(data, size, NULL, NULL, 0, &k);
        (void)dosipas_issuing_time(NULL, &x);
        (void)dosipas_end_of_validity_time(NULL, &x);
        (void)dosipas_dynamic_content_time(NULL, &x);
        (void)dosipas_open_ticket_validity_window(NULL, NULL, &x, &x);
        (void)dosipas_first_rail_ticket(NULL);
        char l[1][DOSIPAS_SUMMARY_LINE_SIZE];
        (void)dosipas_summary(NULL, NULL, l, 1);
        dosipas_to_ascii(NULL, l[0], sizeof l[0]);
        dosipas_to_ascii("x", l[0], 0);
    }
    if (dosipas_decode(data, size, &arena, &t) != DOSIPAS_OK) {
        if (t) abort();
        return 0;
    }
    if (!t) abort();
    size_t needed = 0;
    /* Short JSON buffers now and then for the truncation paths (snprintf semantics). */
    size_t jcap = (size > 1 && (data[size - 2] & 7) == 7) ? (size_t)data[size - 2] * 4 : sizeof json;
    dosipas_json_write(t, json, jcap, &needed);
    if (jcap && needed < jcap && json[needed] != '\0') abort();
    int64_t v;
    dosipas_issuing_time(t, &v);
    dosipas_end_of_validity_time(t, &v);
    dosipas_dynamic_content_time(t, &v);
    char lines[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
    dosipas_summary(t, NULL, lines, (size > 2 && (data[size - 3] & 3) == 3) ? data[size - 3] % 9 : DOSIPAS_SUMMARY_MAX_LINES);
    uint8_t sb[4096];
    size_t n;
    dosipas_level1_signed_bytes(data, size, t, sb, sizeof sb, &n);
    dosipas_level2_signed_bytes(data, size, t, sb, sizeof sb, &n);
    /* Arbitrary bit ranges, including out-of-range ones. */
    if (size > 8) {
        uint32_t off = ((uint32_t)data[1] << 8 | data[2]) % (uint32_t)(size * 8 + 16);
        uint32_t bl = ((uint32_t)data[3] << 8 | data[4]) % (uint32_t)(size * 8 + 16);
        dosipas_extract_bits(data, size, off, bl, sb, (data[5] & 1) ? sizeof sb : (size_t)(data[6] & 15), &n);
    }
    const dosipas_rail_ticket_t *rt = dosipas_first_rail_ticket(t);
    for (size_t i = 0; rt && i < rt->transportDocument_count; i++) {
        if (rt->transportDocument[i].openTicket && rt->issuingDetail) {
            int64_t a, b;
            dosipas_open_ticket_validity_window(rt->transportDocument[i].openTicket, rt->issuingDetail, &a, &b);
        }
    }
    if (arena.used > arena.cap) abort();
    return 0;
}
