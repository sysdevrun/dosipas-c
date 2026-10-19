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
    dosipas_summary(t, NULL, lines, DOSIPAS_SUMMARY_MAX_LINES);
    uint8_t sb[4096];
    size_t n;
    dosipas_level1_signed_bytes(data, size, t, sb, sizeof sb, &n);
    dosipas_level2_signed_bytes(data, size, t, sb, sizeof sb, &n);
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
