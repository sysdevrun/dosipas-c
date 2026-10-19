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
static uint8_t arena_buf[DOSIPAS_RECOMMENDED_ARENA_SIZE + 8];

/* Walk the tree through the public accessors, looking every member up again by name. */
static void walk(const dosipas_value_t *v, int depth) {
    for (; v && depth < 64; v = v->next) {
        const char *name = dosipas_value_name(v);
        (void)dosipas_value_enum_name(v);
        (void)dosipas_value_choice_key(v);
        (void)dosipas_value_item(v, v->aux);
        (void)dosipas_value_item(v, 0);
        if (v->kind == DOSIPAS_V_SEQUENCE) {
            for (const dosipas_value_t *m = v->u.child; m; m = m->next) {
                const char *mn = dosipas_value_name(m);
                if (mn && !dosipas_value_field(v, mn)) abort();
            }
            (void)dosipas_value_field(v, "no-such-field");
        }
        if (name && depth == 0) (void)dosipas_value_field(v, name);
        if (v->kind == DOSIPAS_V_SEQUENCE || v->kind == DOSIPAS_V_SEQUENCE_OF || v->kind == DOSIPAS_V_CHOICE)
            walk(v->u.child, depth + 1);
    }
}
static char json[16384];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    static int once;
    if (!once) { /* argument checks and every error string, once */
        once = 1;
        for (int e = -20; e <= 20; e++) (void)dosipas_strerror((dosipas_err_t)e);
        dosipas_value_t *o;
        (void)dosipas_decode_value(NULL, 1, 0, NULL, NULL, NULL);
        (void)dosipas_decode_value(data, 0, 0, NULL, &o, NULL);
        (void)dosipas_value_field(NULL, "x");
        (void)dosipas_value_item(NULL, 0);
        (void)dosipas_value_enum_name(NULL);
        (void)dosipas_value_choice_key(NULL);
        (void)dosipas_value_name(NULL);
    }
    uint8_t sel = data[0];
    dosipas_arena_t arena;
    /* Top 3 bits pick a smaller arena now and then to reach the exhaustion paths. */
    size_t cap = (sel >> 5) == 7 ? 256 + (size_t)(size & 0xff) * 32 : sizeof arena_buf;
    /* Misaligned buffer start and tiny sizes for the arena alignment paths. */
    size_t off = (sel >> 5) == 6 ? (size_t)(sel & 7) : 0;
    dosipas_arena_init(&arena, arena_buf + off, (sel >> 5) == 6 && (size & 1) ? off : cap);
    dosipas_value_t *v = NULL;
    uint32_t fail_bit = 0;
    dosipas_err_t err = dosipas_decode_value(data + 1, size - 1, roots[sel & 7], &arena, &v, &fail_bit);
    if (!dosipas_strerror(err)) abort();
    if (err != DOSIPAS_OK) return 0;
    if (!v) abort();
    walk(v, 0);
    size_t needed = 0;
    size_t jcap = (sel & 0x18) == 0x18 ? (size_t)(size % 97) : sizeof json;
    dosipas_json_write_value(v, json, jcap, &needed);
    if (jcap && needed < jcap && json[needed] != '\0') abort();
    if (arena.used > arena.cap) abort();
    return 0;
}
