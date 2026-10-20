/*
 * libFuzzer target: dosipas_ecdsa_verify on its own (point parsing and decompression,
 * DER and raw r||s signatures, curve/hash names).
 *
 * Input: [curve sel][hash sel][key length: 2 BE][key][sig length: 2 BE][sig][data].
 *
 * SPDX-License-Identifier: MIT
 */
#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dosipas_verify.h"

static const char *const curves[] = {"P-256", "P-384", "P-521", "P-192", "", "secp256k1", "P-2560", "p-256"};
static const char *const hashes[] = {"SHA-256", "SHA-384", "SHA-512", "SHA-1", "", "SHA-224", "SHA-5120", "sha-256"};

static size_t take(const uint8_t **p, size_t *left) {
    if (*left < 2) { *left = 0; return 0; }
    size_t n = ((size_t)(*p)[0] << 8) | (*p)[1];
    *p += 2;
    *left -= 2;
    return n > *left ? *left : n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    const char *curve = curves[data[0] & 7], *hash = hashes[data[1] & 7];
    size_t ecap = (data[1] & 0x80) ? (size_t)(data[0] >> 4) : 128;
    const uint8_t *p = data + 2;
    size_t left = size - 2;
    size_t kl = take(&p, &left);
    const uint8_t *key = p;
    p += kl; left -= kl;
    size_t sl = take(&p, &left);
    const uint8_t *sig = p;
    p += sl; left -= sl;
    bool valid = false;
    char err[128];
    memset(err, 'x', sizeof err);
    dosipas_ecdsa_verify(curve, hash, key, kl, sig, sl, p, left, &valid, ecap ? err : NULL, ecap);
    if (ecap && strnlen(err, ecap) == ecap) abort();
    return 0;
}
