/*
 * dosipas-c: signature verification with mbedTLS.
 *
 * Mirrors dosipas-ts verifier.ts / oids.ts / signature-utils.ts:
 *  - ECDSA on P-256, P-384, P-521 with SHA-256/384/512 (mbedTLS). DSA and RSA
 *    are reported as unsupported, with the same error text as dosipas-ts.
 *  - Algorithm OIDs are resolved like `resolveAlgorithms`: the barcode's OID
 *    wins, a caller-supplied OID fills a gap, a disagreement is an error.
 *  - Public keys: compressed point (02/03, decompressed here since mbedTLS
 *    cannot), uncompressed point (04), SPKI DER or X.509 certificate.
 *  - Signatures: DER SEQUENCE{r,s} or raw r||s (dosipas-ts only accepts DER;
 *    raw acceptance is the one documented divergence). High-S is accepted.
 *
 * Compiled in when DOSIPAS_WITH_MBEDTLS is non-zero (automatic on ESP32).
 * Without it every function returns DOSIPAS_ERR_UNSUPPORTED.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_VERIFY_H
#define DOSIPAS_VERIFY_H

#include "dosipas.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum dosipas_alg_source {
    DOSIPAS_ALG_SOURCE_NONE = 0,
    DOSIPAS_ALG_SOURCE_BARCODE,
    DOSIPAS_ALG_SOURCE_CONFIGURED,
    DOSIPAS_ALG_SOURCE_MIXED,
} dosipas_alg_source_t;

typedef struct dosipas_verify_result {
    bool valid;
    char error[256];      /* empty when valid */
    char algorithm[40];   /* e.g. "ECDSA P-256 with SHA-256", empty when unknown */
    dosipas_alg_source_t algorithmSource;
} dosipas_verify_result_t;

/* Caller-supplied OIDs used only when the barcode omits its own (dotted decimal, NULL = none). */
typedef struct dosipas_level2_algorithms {
    const char *keyAlg;
    const char *signingAlg;
} dosipas_level2_algorithms_t;

/* Level 1 key material: public key bytes plus optional algorithm OIDs. */
typedef struct dosipas_level1_key {
    const uint8_t *publicKey; /* raw EC point, SPKI DER or X.509 certificate */
    size_t publicKey_len;
    const char *keyAlg;       /* NULL = none */
    const char *signingAlg;   /* NULL = none */
} dosipas_level1_key_t;

/* One entry of a caller-maintained level 1 key table. An issuer is matched
 * by securityProviderNum (0 = not set) or securityProviderIA5 (NULL = not set),
 * plus keyId (-1 = any). */
typedef struct dosipas_level1_key_entry {
    int32_t securityProviderNum;
    const char *securityProviderIA5;
    int32_t keyId;
    dosipas_level1_key_t key;
} dosipas_level1_key_entry_t;

/* Find the key for a ticket's issuer + keyId, or NULL. */
const dosipas_level1_key_t *dosipas_level1_key_lookup(const dosipas_level1_key_entry_t *entries, size_t count,
                                                      const dosipas_ticket_t *ticket);

/*
 * Verify the level 2 signature with the public key embedded in the barcode.
 * `payload` must be the bytes `ticket` was decoded from. `scratch` provides
 * temporary memory for the signed bytes (its `used` mark is restored); it may
 * be the arena the ticket lives in. Returns DOSIPAS_OK when a verdict was
 * reached (valid or not, see *out), an error code for bad arguments.
 */
dosipas_err_t dosipas_verify_level2(const uint8_t *payload, size_t len, const dosipas_ticket_t *ticket,
                                    const dosipas_level2_algorithms_t *algorithms, dosipas_arena_t *scratch,
                                    dosipas_verify_result_t *out);

/* Verify the level 1 signature with a caller-supplied key. */
dosipas_err_t dosipas_verify_level1(const uint8_t *payload, size_t len, const dosipas_ticket_t *ticket,
                                    const dosipas_level1_key_t *key, dosipas_arena_t *scratch,
                                    dosipas_verify_result_t *out);

/* Low-level: verify an ECDSA signature over `data`. curve: "P-256"/"P-384"/"P-521",
 * hash: "SHA-256"/"SHA-384"/"SHA-512". Public key and signature in any of the
 * accepted formats. Returns DOSIPAS_OK with *valid set, or fills `error`. */
dosipas_err_t dosipas_ecdsa_verify(const char *curve, const char *hash, const uint8_t *public_key, size_t public_key_len,
                                   const uint8_t *signature, size_t signature_len, const uint8_t *data, size_t data_len,
                                   bool *valid, char *error, size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif /* DOSIPAS_VERIFY_H */
