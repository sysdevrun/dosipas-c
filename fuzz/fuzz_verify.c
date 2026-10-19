/*
 * libFuzzer target: decode then verify level 1 and level 2 with mbedTLS.
 *
 * Input: [keyAlg sel][signingAlg sel][key length: 2 bytes BE][level 1 key][barcode].
 * The level 1 key is a raw EC point, an SPKI DER or an X.509 certificate (whatever the
 * fuzzer makes of it); the selectors pick the configured OIDs (0 = none, 1-3 = P-256/384/521,
 * other = an unsupported OID). Level 2 runs with the algorithms from the barcode and, for odd
 * keyAlg selectors, configured ones. Results feed dosipas_summary_ex.
 *
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dosipas.h"
#include "dosipas_summary.h"
#include "dosipas_verify.h"

static const char *const key_oids[] = {NULL, "1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35",
                                       "1.2.840.113549.1.1.1", "1.2.840.10040.4.1", "", "1.2.3"};
static const char *const sig_oids[] = {NULL, "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4",
                                       "1.2.840.113549.1.1.11", "2.16.840.1.101.3.4.3.2", "", "1.2.3"};
static uint8_t arena_buf[DOSIPAS_RECOMMENDED_ARENA_SIZE];
static uint8_t scratch_buf[DOSIPAS_RECOMMENDED_ARENA_SIZE];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    uint8_t ks = data[0], ss = data[1];
    size_t klen = ((size_t)data[2] << 8) | data[3];
    if (klen > size - 4) klen = size - 4;
    const uint8_t *key = data + 4;
    const uint8_t *payload = key + klen;
    size_t len = size - 4 - klen;

    dosipas_arena_t arena;
    dosipas_arena_init(&arena, arena_buf, sizeof arena_buf);
    dosipas_ticket_t *t = NULL;
    if (dosipas_decode(payload, len, &arena, &t) != DOSIPAS_OK) return 0;

    dosipas_arena_t scratch;
    /* Small scratch arenas now and then for the "scratch too small" paths. */
    dosipas_arena_init(&scratch, scratch_buf, (ss & 0xc0) == 0xc0 ? (size_t)(ks & 0x3f) * 16 : sizeof scratch_buf);
    dosipas_verify_result_t l1, l2;
    dosipas_level2_algorithms_t algs = {key_oids[ks & 7], sig_oids[ss & 7]};
    dosipas_verify_level2(payload, len, t, (ks & 8) ? &algs : NULL, &scratch, &l2);
    dosipas_level1_key_t k = {key, klen, key_oids[ks & 7], sig_oids[ss & 7]};
    dosipas_arena_init(&scratch, scratch_buf, sizeof scratch_buf);
    dosipas_verify_level1(payload, len, t, &k, &scratch, &l1);
    if (l1.valid && l1.error[0]) abort();
    if (strnlen(l1.error, sizeof l1.error) == sizeof l1.error || strnlen(l2.error, sizeof l2.error) == sizeof l2.error) abort();

    dosipas_level1_key_entry_t entry = {0};
    entry.securityProviderNum = t->level1Data.securityProviderNum;
    entry.keyId = t->level1Data.keyId;
    entry.key = k;
    dosipas_level1_key_lookup(&entry, 1, t);

    char lines[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
    dosipas_summary_ex(t, (ks & 16) ? &l1 : NULL, (ks & 32) ? &l2 : NULL, lines, DOSIPAS_SUMMARY_MAX_LINES);
    return 0;
}
