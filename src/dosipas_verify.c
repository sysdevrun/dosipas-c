/*
 * dosipas-c: signature verification (see dosipas_verify.h).
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>

#include "dosipas_internal.h"
#include "dosipas_verify.h"

#ifndef DOSIPAS_WITH_MBEDTLS
#if defined(ESP_PLATFORM) || defined(ARDUINO_ARCH_ESP32) || defined(IDF_VER)
#define DOSIPAS_WITH_MBEDTLS 1
#else
#define DOSIPAS_WITH_MBEDTLS 0
#endif
#endif

/* ------------------------------------------------------------------------- */
/* OID tables and algorithm resolution (oids.ts)                             */
/* ------------------------------------------------------------------------- */

typedef struct {
    const char *oid;
    const char *hash; /* "SHA-256" ... */
    const char *type; /* "ECDSA", "DSA", "RSA" */
} signing_alg_t;

typedef struct {
    const char *oid;
    const char *type;  /* "EC", "RSA" */
    const char *curve; /* "P-256" ... or NULL */
} key_alg_t;

static const signing_alg_t SIGNING_ALGORITHMS[] = {
    {"1.2.840.10045.4.3.2", "SHA-256", "ECDSA"},
    {"1.2.840.10045.4.3.3", "SHA-384", "ECDSA"},
    {"1.2.840.10045.4.3.4", "SHA-512", "ECDSA"},
    {"2.16.840.1.101.3.4.3.1", "SHA-224", "DSA"},
    {"2.16.840.1.101.3.4.3.2", "SHA-256", "DSA"},
    {"1.2.840.113549.1.1.11", "SHA-256", "RSA"},
};

static const key_alg_t KEY_ALGORITHMS[] = {
    {"1.2.840.10045.3.1.7", "EC", "P-256"},
    {"1.3.132.0.34", "EC", "P-384"},
    {"1.3.132.0.35", "EC", "P-521"},
    {"1.2.840.113549.1.1.1", "RSA", NULL},
};

static const signing_alg_t *signing_alg(const char *oid) {
    for (size_t i = 0; oid && i < sizeof SIGNING_ALGORITHMS / sizeof *SIGNING_ALGORITHMS; i++)
        if (strcmp(SIGNING_ALGORITHMS[i].oid, oid) == 0) return &SIGNING_ALGORITHMS[i];
    return NULL;
}

static const key_alg_t *key_alg(const char *oid) {
    for (size_t i = 0; oid && i < sizeof KEY_ALGORITHMS / sizeof *KEY_ALGORITHMS; i++)
        if (strcmp(KEY_ALGORITHMS[i].oid, oid) == 0) return &KEY_ALGORITHMS[i];
    return NULL;
}

/* ^\d+(?:\.\d+)+$ */
static bool is_oid(const char *s) {
    int groups = 0;
    if (!s) return false;
    while (*s) {
        if (!(*s >= '0' && *s <= '9')) return false;
        while (*s >= '0' && *s <= '9') s++;
        groups++;
        if (*s == '.') {
            s++;
            if (!(*s >= '0' && *s <= '9')) return false;
        } else if (*s) {
            return false;
        }
    }
    return groups >= 2;
}

typedef struct {
    bool ok;
    const signing_alg_t *signing;
    const key_alg_t *key;
    const char *curve;
    char description[40];
    dosipas_alg_source_t source;
} resolved_t;

static void describe_oid(char *buf, size_t cap, bool signing, const char *oid) {
    if (signing) {
        const signing_alg_t *a = signing_alg(oid);
        if (a) snprintf(buf, cap, "'%s' (%s with %s)", oid, a->type, a->hash);
        else snprintf(buf, cap, "'%s'", oid);
    } else {
        const key_alg_t *a = key_alg(oid);
        if (a) snprintf(buf, cap, "'%s' (%s)", oid, a->curve ? a->curve : a->type);
        else snprintf(buf, cap, "'%s'", oid);
    }
}

/* pickOid: returns false and fills `error` on failure; *oid may stay NULL. */
static bool pick_oid(int level, bool signing, const char *barcode, const char *configured, const char **oid,
                     dosipas_alg_source_t *source, char *error, size_t cap) {
    const char *field = signing ? "SigningAlg" : "KeyAlg";
    const char *what = signing ? "signing" : "key";
    *oid = NULL;
    *source = DOSIPAS_ALG_SOURCE_NONE;
    if (configured && !is_oid(configured)) {
        snprintf(error, cap,
                 "Invalid configured level %d %s algorithm: '%s'. Expected a dotted-decimal OID such as '%s' - see %s in "
                 "src/oids.ts for the accepted values.",
                 level, what, configured, signing ? "1.2.840.10045.4.3.2" : "1.2.840.10045.3.1.7",
                 signing ? "SIGNING_ALGORITHMS" : "KEY_ALGORITHMS");
        return false;
    }
    if (barcode && configured && strcmp(barcode, configured) != 0) {
        char a[64], b[64];
        describe_oid(a, sizeof a, signing, barcode);
        describe_oid(b, sizeof b, signing, configured);
        snprintf(error, cap,
                 "Level %d %s algorithm mismatch: the barcode declares %s in level%d%s, but %s was configured. Remove the "
                 "override, or fix it to match the barcode.",
                 level, what, a, level, field, b);
        return false;
    }
    if (barcode) {
        *oid = barcode;
        *source = DOSIPAS_ALG_SOURCE_BARCODE;
    } else if (configured) {
        *oid = configured;
        *source = DOSIPAS_ALG_SOURCE_CONFIGURED;
    }
    return true;
}

static resolved_t resolve_algorithms(int level, const char *bc_signing, const char *bc_key, const char *cf_signing,
                                     const char *cf_key, char *error, size_t cap) {
    resolved_t r;
    memset(&r, 0, sizeof r);
    const char *sig_oid, *key_oid;
    dosipas_alg_source_t sig_src, key_src;
    if (!pick_oid(level, true, bc_signing, cf_signing, &sig_oid, &sig_src, error, cap)) return r;
    if (!sig_oid) {
        snprintf(error, cap, "Missing level %d signing algorithm: the barcode has no level%dSigningAlg OID and no signingAlg was configured.",
                 level, level);
        return r;
    }
    r.signing = signing_alg(sig_oid);
    if (!r.signing) {
        snprintf(error, cap, "Unsupported signing algorithm: %s", sig_oid);
        return r;
    }
    if (!pick_oid(level, false, bc_key, cf_key, &key_oid, &key_src, error, cap)) return r;
    if (key_oid) {
        r.key = key_alg(key_oid);
        if (!r.key) {
            snprintf(error, cap, "Cannot determine curve from key algorithm: %s", key_oid);
            return r;
        }
        r.curve = r.key->curve;
    }
    if (strcmp(r.signing->type, "ECDSA") == 0 && !r.curve) {
        if (key_oid) snprintf(error, cap, "Cannot determine curve from key algorithm: %s", key_oid);
        else
            snprintf(error, cap,
                     "Missing level %d key algorithm: the barcode has no level%dKeyAlg OID and no keyAlg was configured. ECDSA "
                     "verification needs it to identify the curve.",
                     level, level);
        return r;
    }
    if (key_src == DOSIPAS_ALG_SOURCE_NONE) r.source = sig_src;
    else r.source = sig_src == key_src ? sig_src : DOSIPAS_ALG_SOURCE_MIXED;
    if (r.curve) snprintf(r.description, sizeof r.description, "%s %s with %s", r.signing->type, r.curve, r.signing->hash);
    else snprintf(r.description, sizeof r.description, "%s with %s", r.signing->type, r.signing->hash);
    r.ok = true;
    return r;
}

#if DOSIPAS_WITH_MBEDTLS

/* ------------------------------------------------------------------------- */
/* DER helpers (signature-utils.ts, with bounds checks)                      */
/* ------------------------------------------------------------------------- */

static bool der_len(const uint8_t *p, size_t n, size_t *off, size_t *len) {
    if (*off >= n) return false;
    uint32_t l = p[(*off)++];
    if (l & 0x80u) {
        unsigned k = l & 0x7fu;
        if (k == 0 || k > 4 || *off + k > n) return false;
        l = 0;
        for (unsigned i = 0; i < k; i++) l = (l << 8) | p[(*off)++];
    }
    if (l > n - *off) return false;
    *len = l;
    return true;
}

/* Skip one TLV element. */
static bool der_skip(const uint8_t *p, size_t n, size_t *off) {
    size_t len;
    if (*off >= n) return false;
    (*off)++;
    if (!der_len(p, n, off, &len)) return false;
    *off += len;
    return true;
}

/* SPKI: SEQUENCE { SEQUENCE algorithm, BIT STRING key }. */
static bool point_from_spki(const uint8_t *p, size_t n, const uint8_t **pt, size_t *pt_len) {
    size_t off = 0, len;
    if (n == 0 || p[off++] != 0x30 || !der_len(p, n, &off, &len)) return false;
    if (off >= n || p[off++] != 0x30 || !der_len(p, n, &off, &len)) return false;
    off += len;
    if (off >= n || p[off++] != 0x03 || !der_len(p, n, &off, &len)) return false;
    if (len < 2) return false;
    *pt = p + off + 1; /* skip unused-bits byte */
    *pt_len = len - 1;
    return true;
}

/* X.509: Certificate { tbsCertificate { [0] version?, serial, sigAlg, issuer, validity, subject, SPKI ... } ... }. */
static bool point_from_x509(const uint8_t *p, size_t n, const uint8_t **pt, size_t *pt_len) {
    size_t off = 0, len;
    if (n == 0 || p[off++] != 0x30 || !der_len(p, n, &off, &len)) return false;
    if (off >= n || p[off++] != 0x30 || !der_len(p, n, &off, &len)) return false;
    if (off < n && p[off] == 0xa0 && !der_skip(p, n, &off)) return false;
    for (int i = 0; i < 5; i++)
        if (!der_skip(p, n, &off)) return false;
    if (off >= n || p[off] != 0x30) return false;
    size_t spki_start = off, o2 = off + 1;
    if (!der_len(p, n, &o2, &len)) return false;
    return point_from_spki(p + spki_start, o2 + len - spki_start, pt, pt_len);
}

static const uint8_t SPKI_P256_HEADER[26] = {0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                                             0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00};

/* extractEcPublicKeyPoint */
static bool extract_point(const uint8_t *key, size_t n, const uint8_t **pt, size_t *pt_len, char *error, size_t cap) {
    if (n == 0) {
        snprintf(error, cap, "Unrecognized public key format: empty key");
        return false;
    }
    if (key[0] == 0x04 || key[0] == 0x02 || key[0] == 0x03) {
        *pt = key;
        *pt_len = n;
        return true;
    }
    if (key[0] == 0x30 && n > 33) {
        if (n == 91 && memcmp(key, SPKI_P256_HEADER, 26) == 0) {
            *pt = key + 26;
            *pt_len = 65;
            return true;
        }
        if (n > 100 && point_from_x509(key, n, pt, pt_len)) return true;
        if (point_from_spki(key, n, pt, pt_len)) return true;
        snprintf(error, cap, "Invalid SPKI or certificate structure");
        return false;
    }
    snprintf(error, cap, "Unrecognized public key format: first byte 0x%x, length %u", key[0], (unsigned)n);
    return false;
}

/* derToRaw: DER SEQUENCE{INTEGER r, INTEGER s} -> r||s of 2*clen bytes. Raw
 * r||s input (exactly 2*clen bytes, not starting with 0x30) is passed through. */
static bool signature_to_raw(const uint8_t *sig, size_t n, size_t clen, uint8_t *raw, char *error, size_t cap) {
    memset(raw, 0, clen * 2);
    if (n == 0) {
        snprintf(error, cap, "Invalid DER signature: empty");
        return false;
    }
    if (sig[0] != 0x30) {
        if (n == clen * 2) {
            memcpy(raw, sig, n);
            return true;
        }
        snprintf(error, cap, "Invalid DER signature: expected SEQUENCE tag 0x30, got 0x%x", sig[0]);
        return false;
    }
    size_t off = 1, seq_len;
    if (!der_len(sig, n, &off, &seq_len)) {
        snprintf(error, cap, "Invalid DER signature: bad length");
        return false;
    }
    for (int i = 0; i < 2; i++) {
        size_t ilen;
        if (off >= n || sig[off++] != 0x02) {
            snprintf(error, cap, "Invalid DER signature: expected INTEGER tag for %s", i ? "s" : "r");
            return false;
        }
        if (!der_len(sig, n, &off, &ilen)) {
            snprintf(error, cap, "Invalid DER signature: bad %s length", i ? "s" : "r");
            return false;
        }
        size_t pad = ilen > clen ? ilen - clen : 0; /* strip leading 0x00 padding like derToRaw */
        size_t take = ilen - pad;
        memcpy(raw + (size_t)i * clen + (clen - take), sig + off + pad, take);
        off += ilen;
    }
    return true;
}

static size_t curve_component_length(const char *curve) {
    if (strcmp(curve, "P-256") == 0) return 32;
    if (strcmp(curve, "P-384") == 0) return 48;
    if (strcmp(curve, "P-521") == 0) return 66;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* ECDSA with mbedTLS                                                        */
/* ------------------------------------------------------------------------- */

#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

/* y = sqrt(x^3 - 3x + b) mod p with p = 3 mod 4, choosing the parity in `odd`.
 * All three NIST curves have a = -3, so grp->A is not read (it is left unset
 * by mbedTLS for these curves). */
static int decompress_point(mbedtls_ecp_group *grp, const uint8_t *x_bytes, size_t clen, bool odd, uint8_t *y_out) {
    mbedtls_mpi x, y, t, e;
    int ret;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);
    mbedtls_mpi_init(&t);
    mbedtls_mpi_init(&e);
    if ((ret = mbedtls_mpi_read_binary(&x, x_bytes, clen)) != 0) goto out;
    if (mbedtls_mpi_cmp_mpi(&x, &grp->P) >= 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto out;
    }
    /* y = x^2 */
    if ((ret = mbedtls_mpi_mul_mpi(&y, &x, &x)) != 0) goto out;
    if ((ret = mbedtls_mpi_mod_mpi(&y, &y, &grp->P)) != 0) goto out;
    /* y = x^2 - 3 */
    if ((ret = mbedtls_mpi_sub_int(&y, &y, 3)) != 0) goto out;
    /* y = (x^2 - 3) * x = x^3 - 3x */
    if ((ret = mbedtls_mpi_mul_mpi(&y, &y, &x)) != 0) goto out;
    /* + b */
    if ((ret = mbedtls_mpi_add_mpi(&y, &y, &grp->B)) != 0) goto out;
    if ((ret = mbedtls_mpi_mod_mpi(&y, &y, &grp->P)) != 0) goto out;
    /* e = (p + 1) / 4 */
    if ((ret = mbedtls_mpi_add_int(&e, &grp->P, 1)) != 0) goto out;
    if ((ret = mbedtls_mpi_shift_r(&e, 2)) != 0) goto out;
    /* y = y^e mod p */
    if ((ret = mbedtls_mpi_exp_mod(&t, &y, &e, &grp->P, NULL)) != 0) goto out;
    /* check t^2 == y (x must be on the curve) */
    if ((ret = mbedtls_mpi_mul_mpi(&e, &t, &t)) != 0) goto out;
    if ((ret = mbedtls_mpi_mod_mpi(&e, &e, &grp->P)) != 0) goto out;
    if (mbedtls_mpi_cmp_mpi(&e, &y) != 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto out;
    }
    if ((mbedtls_mpi_get_bit(&t, 0) != 0) != odd) {
        if ((ret = mbedtls_mpi_sub_mpi(&t, &grp->P, &t)) != 0) goto out;
    }
    ret = mbedtls_mpi_write_binary(&t, y_out, clen);
out:
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);
    mbedtls_mpi_free(&t);
    mbedtls_mpi_free(&e);
    return ret;
}

dosipas_err_t dosipas_ecdsa_verify(const char *curve, const char *hash, const uint8_t *public_key, size_t public_key_len,
                                   const uint8_t *signature, size_t signature_len, const uint8_t *data, size_t data_len,
                                   bool *valid, char *error, size_t error_cap) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    uint8_t digest[64], raw_sig[2 * 66], point[1 + 2 * 66];
    size_t clen, point_len, hlen;
    const uint8_t *pt;
    mbedtls_ecp_group_id gid;
    mbedtls_md_type_t md;
    int ret;

    if (!curve || !hash || !public_key || !signature || !valid || (!data && data_len)) return DOSIPAS_ERR_ARG;
    *valid = false;
    if (error_cap) error[0] = '\0';

    clen = curve_component_length(curve);
    if (strcmp(curve, "P-256") == 0) gid = MBEDTLS_ECP_DP_SECP256R1;
    else if (strcmp(curve, "P-384") == 0) gid = MBEDTLS_ECP_DP_SECP384R1;
    else if (strcmp(curve, "P-521") == 0) gid = MBEDTLS_ECP_DP_SECP521R1;
    else {
        snprintf(error, error_cap, "Unsupported curve: %s", curve);
        return DOSIPAS_OK;
    }
    if (strcmp(hash, "SHA-256") == 0) md = MBEDTLS_MD_SHA256, hlen = 32;
    else if (strcmp(hash, "SHA-384") == 0) md = MBEDTLS_MD_SHA384, hlen = 48;
    else if (strcmp(hash, "SHA-512") == 0) md = MBEDTLS_MD_SHA512, hlen = 64;
    else {
        snprintf(error, error_cap, "Unsupported hash: %s", hash);
        return DOSIPAS_OK;
    }

    if (!signature_to_raw(signature, signature_len, clen, raw_sig, error, error_cap)) return DOSIPAS_OK;
    if (!extract_point(public_key, public_key_len, &pt, &point_len, error, error_cap)) return DOSIPAS_OK;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_ecp_group_load(&grp, gid)) != 0) {
        snprintf(error, error_cap, "mbedtls_ecp_group_load failed (-0x%04x)", (unsigned)-ret);
        goto out;
    }
    if ((pt[0] == 0x02 || pt[0] == 0x03) && point_len == 1 + clen) {
        point[0] = 0x04;
        memcpy(point + 1, pt + 1, clen);
        if ((ret = decompress_point(&grp, pt + 1, clen, pt[0] == 0x03, point + 1 + clen)) != 0) {
            snprintf(error, error_cap, "Invalid compressed public key point (-0x%04x)", (unsigned)-ret);
            goto out;
        }
        pt = point;
        point_len = 1 + 2 * clen;
    } else if (pt[0] != 0x04 || point_len != 1 + 2 * clen) {
        snprintf(error, error_cap, "Public key point length %u does not match %s", (unsigned)point_len, curve);
        goto out;
    }
    if ((ret = mbedtls_ecp_point_read_binary(&grp, &Q, pt, point_len)) != 0 ||
        (ret = mbedtls_ecp_check_pubkey(&grp, &Q)) != 0) {
        snprintf(error, error_cap, "Invalid public key point (-0x%04x)", (unsigned)-ret);
        goto out;
    }
    if ((ret = mbedtls_md(mbedtls_md_info_from_type(md), data, data_len, digest)) != 0) {
        snprintf(error, error_cap, "Hashing failed (-0x%04x)", (unsigned)-ret);
        goto out;
    }
    if ((ret = mbedtls_mpi_read_binary(&r, raw_sig, clen)) != 0 ||
        (ret = mbedtls_mpi_read_binary(&s, raw_sig + clen, clen)) != 0) {
        snprintf(error, error_cap, "Signature read failed (-0x%04x)", (unsigned)-ret);
        goto out;
    }
    ret = mbedtls_ecdsa_verify(&grp, digest, hlen, &Q, &r, &s);
    if (ret == 0) *valid = true;
    else if (ret != MBEDTLS_ERR_ECP_VERIFY_FAILED && ret != MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
        snprintf(error, error_cap, "mbedtls_ecdsa_verify failed (-0x%04x)", (unsigned)-ret);

out:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return DOSIPAS_OK;
}

#else /* !DOSIPAS_WITH_MBEDTLS */

dosipas_err_t dosipas_ecdsa_verify(const char *curve, const char *hash, const uint8_t *public_key, size_t public_key_len,
                                   const uint8_t *signature, size_t signature_len, const uint8_t *data, size_t data_len,
                                   bool *valid, char *error, size_t error_cap) {
    (void)curve; (void)hash; (void)public_key; (void)public_key_len; (void)signature; (void)signature_len; (void)data;
    (void)data_len;
    if (valid) *valid = false;
    if (error_cap) snprintf(error, error_cap, "dosipas-c built without mbedTLS");
    return DOSIPAS_ERR_UNSUPPORTED;
}

#endif

/* ------------------------------------------------------------------------- */
/* Level verification (verifier.ts)                                          */
/* ------------------------------------------------------------------------- */

static dosipas_err_t verify_level(int level, const uint8_t *payload, size_t len, const dosipas_ticket_t *t,
                                  dosipas_bytes_t signature, const uint8_t *key, size_t key_len, const char *bc_signing,
                                  const char *bc_key, const char *cf_signing, const char *cf_key,
                                  uint32_t bit_offset, uint32_t bit_length, dosipas_arena_t *scratch,
                                  dosipas_verify_result_t *out) {
    memset(out, 0, sizeof *out);
    if (!payload || !t || !scratch || len != t->payload_len) return DOSIPAS_ERR_ARG;

    if (!signature.ptr) {
        snprintf(out->error, sizeof out->error, "Missing level %d signature", level);
        return DOSIPAS_OK;
    }
    if (!key) {
        snprintf(out->error, sizeof out->error, "Missing level %d public key", level);
        return DOSIPAS_OK;
    }
    resolved_t r = resolve_algorithms(level, bc_signing, bc_key, cf_signing, cf_key, out->error, sizeof out->error);
    if (!r.ok) return DOSIPAS_OK;
    snprintf(out->algorithm, sizeof out->algorithm, "%s", r.description);
    out->algorithmSource = r.source;
    if (strcmp(r.signing->type, "ECDSA") != 0) {
        if (level == 2) snprintf(out->error, sizeof out->error, "Unsupported signing type for level 2: %s", r.signing->type);
        else if (strcmp(r.signing->type, "DSA") == 0)
            snprintf(out->error, sizeof out->error, "DSA verification not supported (algorithm: %s)", r.description);
        else {
            snprintf(out->error, sizeof out->error, "Unsupported algorithm type: %s", r.signing->type);
            out->algorithm[0] = '\0';
            out->algorithmSource = DOSIPAS_ALG_SOURCE_NONE;
        }
        return DOSIPAS_OK;
    }

    /* Signed bytes: copied out of the payload into the scratch arena. */
    size_t mark = scratch->used, n = 0;
    size_t cap = ((size_t)bit_length + 7u) / 8u + 1u;
    uint8_t *signed_bytes = (uint8_t *)ds_arena_alloc(scratch, cap);
    if (!signed_bytes) return DOSIPAS_ERR_ARENA_FULL;
    dosipas_err_t err = dosipas_extract_bits(payload, len, bit_offset, bit_length, signed_bytes, cap, &n);
    if (err != DOSIPAS_OK) {
        scratch->used = mark;
        return err;
    }
    char detail[128];
    bool valid = false;
    err = dosipas_ecdsa_verify(r.curve, r.signing->hash, key, key_len, signature.ptr, signature.len, signed_bytes, n,
                               &valid, detail, sizeof detail);
    scratch->used = mark;
    if (err == DOSIPAS_ERR_UNSUPPORTED) {
        snprintf(out->error, sizeof out->error, "Level %d signature verification error (%s): %s", level, r.description, detail);
        return err;
    }
    if (err != DOSIPAS_OK) return err;
    out->valid = valid;
    if (!valid) {
        if (detail[0])
            snprintf(out->error, sizeof out->error, "Level %d signature verification error (%s): %s", level, r.description, detail);
        else
            snprintf(out->error, sizeof out->error, "Level %d signature verification failed (%s)", level, r.description);
    }
    return DOSIPAS_OK;
}

dosipas_err_t dosipas_verify_level2(const uint8_t *payload, size_t len, const dosipas_ticket_t *t,
                                    const dosipas_level2_algorithms_t *algorithms, dosipas_arena_t *scratch,
                                    dosipas_verify_result_t *out) {
    if (!out) return DOSIPAS_ERR_ARG;
    if (!t) {
        memset(out, 0, sizeof *out);
        return DOSIPAS_ERR_ARG;
    }
    const dosipas_level1_data_t *l1 = &t->level1Data;
    return verify_level(2, payload, len, t, t->level2Signature, l1->level2PublicKey.ptr, l1->level2PublicKey.len,
                        l1->level2SigningAlg, l1->level2KeyAlg, algorithms ? algorithms->signingAlg : NULL,
                        algorithms ? algorithms->keyAlg : NULL, t->level2SignedData_bit_offset,
                        t->level2SignedData_bit_length, scratch, out);
}

dosipas_err_t dosipas_verify_level1(const uint8_t *payload, size_t len, const dosipas_ticket_t *t,
                                    const dosipas_level1_key_t *key, dosipas_arena_t *scratch,
                                    dosipas_verify_result_t *out) {
    if (!out) return DOSIPAS_ERR_ARG;
    if (!t || !key || !key->publicKey) {
        memset(out, 0, sizeof *out);
        return DOSIPAS_ERR_ARG;
    }
    const dosipas_level1_data_t *l1 = &t->level1Data;
    return verify_level(1, payload, len, t, t->level1Signature, key->publicKey, key->publicKey_len, l1->level1SigningAlg,
                        l1->level1KeyAlg, key->signingAlg, key->keyAlg, l1->bit_offset, l1->bit_length, scratch, out);
}
