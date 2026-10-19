/*
 * libFuzzer target: one UPER value of one schema root, without the barcode wrapper.
 *
 * Input: [root selector][UPER bytes]. The selector (byte % 8) picks the header v1/v2,
 * FCB1/2/3, Intercode issuing/dynamic or FDC1 root, so the fuzzer reaches the inner
 * schemas directly instead of having to build a valid barcode around them. The value
 * tree then goes through the JSON writer with a buffer size taken from the input.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "dosipas.h"
#include "dosipas_json.h"
#include "dosipas_schema_names.h"

static const uint16_t roots[8] = {
    DS_ROOT_HEADER_V1,         DS_ROOT_HEADER_V2,         DS_ROOT_RAIL_TICKET_V1,    DS_ROOT_RAIL_TICKET_V2,
    DS_ROOT_RAIL_TICKET_V3,    DS_ROOT_INTERCODE_ISSUING, DS_ROOT_INTERCODE_DYNAMIC, DS_ROOT_DYNAMIC_CONTENT_V1,
};
static uint8_t arena_buf[DOSIPAS_RECOMMENDED_ARENA_SIZE];
static char json[16384];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    uint8_t sel = data[0];
    dosipas_arena_t arena;
    /* Top 3 bits pick a smaller arena now and then to reach the exhaustion paths. */
    size_t cap = (sel >> 5) == 7 ? 256 + (size_t)(size & 0xff) * 32 : sizeof arena_buf;
    dosipas_arena_init(&arena, arena_buf, cap);
    dosipas_value_t *v = NULL;
    uint32_t fail_bit = 0;
    if (dosipas_decode_value(data + 1, size - 1, roots[sel & 7], &arena, &v, &fail_bit) != DOSIPAS_OK) return 0;
    if (!v) abort();
    size_t needed = 0;
    size_t jcap = (sel & 0x18) == 0x18 ? (size_t)(size % 97) : sizeof json;
    dosipas_json_write_value(v, json, jcap, &needed);
    if (jcap && needed < jcap && json[needed] != '\0') abort();
    if (arena.used > arena.cap) abort();
    return 0;
}
