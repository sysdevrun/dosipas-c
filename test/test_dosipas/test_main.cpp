/*
 * dosipas-c test suite (Unity). Runs on the host (CMake/ctest, `pio test -e
 * native`) and on the ESP32 (`pio test -e esp32dev`).
 *
 * Groups (select on the host with command-line arguments, e.g. `dosipas_tests
 * golden robustness`): golden, times, signed, robustness, verify, metrics.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unity.h>

extern "C" {
#include "dosipas.h"
#include "dosipas_json.h"
#include "dosipas_summary.h"
#include "dosipas_verify.h"
#include "fixtures_data.h"
#include "tjson.h"
}

#ifdef ARDUINO
#include <Arduino.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#define NOW_US() ((int64_t)esp_timer_get_time())
#define FREE_HEAP() ((size_t)heap_caps_get_free_size(MALLOC_CAP_8BIT))
#define MIN_FREE_HEAP() ((size_t)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT))
#else
#include <time.h>
static int64_t NOW_US() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}
#define FREE_HEAP() ((size_t)0)
#define MIN_FREE_HEAP() ((size_t)0)
#endif

/* The arena size the library recommends; every fixture must fit with margin. */
#define ARENA_SIZE DOSIPAS_RECOMMENDED_ARENA_SIZE
#define JSON_CAP (16 * 1024)

static uint8_t *g_arena_buf;
static char *g_json;
static uint8_t *g_scratch; /* mutable payload copy for truncation / bit flips */
static dosipas_arena_t g_arena;

/* Peak arena use per fixture, filled by the golden tests, printed by metrics. */
static size_t g_peak[64];

static void setup_buffers(void) {
    if (!g_arena_buf) g_arena_buf = (uint8_t *)malloc(ARENA_SIZE);
    if (!g_json) g_json = (char *)malloc(JSON_CAP);
    if (!g_scratch) g_scratch = (uint8_t *)malloc(4096);
    TEST_ASSERT_NOT_NULL(g_arena_buf);
    TEST_ASSERT_NOT_NULL(g_json);
    TEST_ASSERT_NOT_NULL(g_scratch);
    dosipas_arena_init(&g_arena, g_arena_buf, ARENA_SIZE);
}

static tj_value_t *golden(size_t i) {
    tj_value_t *g = tj_parse(FIXTURES[i].golden, strlen(FIXTURES[i].golden));
    TEST_ASSERT_NOT_NULL_MESSAGE(g, "golden JSON does not parse");
    return g;
}

static dosipas_ticket_t *decode_fixture(size_t i) {
    dosipas_ticket_t *t = NULL;
    dosipas_arena_reset(&g_arena);
    dosipas_err_t err = dosipas_decode(FIXTURES[i].payload, FIXTURES[i].payload_len, &g_arena, &t);
    char msg[128];
    snprintf(msg, sizeof msg, "%s: decode failed: %s at bit %u", FIXTURES[i].name, dosipas_strerror(err), g_arena.fail_bit);
    TEST_ASSERT_EQUAL_MESSAGE(DOSIPAS_OK, err, msg);
    TEST_ASSERT_NOT_NULL(t);
    return t;
}

static size_t hex_to_bytes(const char *hex, uint8_t *out, size_t cap) {
    size_t n = 0;
    for (; hex[0] && hex[1]; hex += 2) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1) break;
        if (n < cap) out[n] = (uint8_t)v;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------------- */
/* golden: decoded JSON equals dosipas-ts output                             */
/* ------------------------------------------------------------------------- */

static void test_golden_json(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        g_peak[i] = g_arena.peak;
        size_t needed = 0;
        dosipas_err_t err = dosipas_json_write(t, g_json, JSON_CAP, &needed);
        TEST_ASSERT_EQUAL_MESSAGE(DOSIPAS_OK, err, "json write");
        tj_value_t *mine = tj_parse(g_json, needed);
        TEST_ASSERT_NOT_NULL_MESSAGE(mine, "my JSON does not parse");
        char diff[600];
        bool same = tj_equal(tj_get(g, "ticket"), mine, diff, sizeof diff);
        if (!same) {
            char msg[700];
            snprintf(msg, sizeof msg, "%s: %s", FIXTURES[i].name, diff);
            TEST_FAIL_MESSAGE(msg);
        }
        tj_free(mine);
        tj_free(g);
    }
}

/* The typed view agrees with the generic tree on a few load-bearing fields. */
static void test_typed_view(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        const tj_value_t *tk = tj_get(g, "ticket");
        TEST_ASSERT_EQUAL_STRING(tj_get(tk, "format")->str, t->format);
        const tj_value_t *l1 = tj_get(tj_get(tk, "level2SignedData"), "level1Data");
        const tj_value_t *spn = tj_get(l1, "securityProviderNum");
        TEST_ASSERT_EQUAL(spn != NULL, t->level1Data.has_securityProviderNum);
        if (spn) TEST_ASSERT_EQUAL_INT64(spn->inum, t->level1Data.securityProviderNum);
        const tj_value_t *ds = tj_get(l1, "dataSequence");
        TEST_ASSERT_EQUAL_UINT(ds->count, t->level1Data.dataSequence_count);
        for (size_t k = 0; k < ds->count; k++) {
            const tj_value_t *e = tj_at(ds, k);
            TEST_ASSERT_EQUAL_STRING(tj_get(e, "dataFormat")->str, t->level1Data.dataSequence[k].dataFormat);
            const tj_value_t *dec = tj_get(e, "decoded");
            TEST_ASSERT_EQUAL(dec != NULL, t->level1Data.dataSequence[k].decoded != NULL);
            if (!dec) continue;
            const dosipas_rail_ticket_t *rt = t->level1Data.dataSequence[k].decoded;
            const tj_value_t *iss = tj_get(dec, "issuingDetail");
            TEST_ASSERT_NOT_NULL(rt->issuingDetail);
            TEST_ASSERT_EQUAL_INT(tj_get(iss, "issuingYear")->inum, rt->issuingDetail->issuingYear);
            TEST_ASSERT_EQUAL_INT(tj_get(iss, "issuingDay")->inum, rt->issuingDetail->issuingDay);
            const tj_value_t *ic = tj_get(iss, "intercodeIssuing");
            TEST_ASSERT_EQUAL(ic != NULL, rt->issuingDetail->intercodeIssuing != NULL);
            if (ic) {
                TEST_ASSERT_EQUAL_STRING(tj_get(ic, "extensionId")->str, rt->issuingDetail->intercodeIssuing->extensionId);
                TEST_ASSERT_EQUAL_UINT(3, rt->issuingDetail->intercodeIssuing->networkId.len);
            }
            const tj_value_t *docs = tj_get(dec, "transportDocument");
            TEST_ASSERT_EQUAL_UINT(docs ? docs->count : 0, rt->transportDocument_count);
            for (size_t d = 0; docs && d < docs->count; d++) {
                const tj_value_t *tkt = tj_get(tj_at(docs, d), "ticket");
                TEST_ASSERT_EQUAL_STRING(tj_get(tkt, "key")->str, rt->transportDocument[d].ticket_key);
                if (strcmp(rt->transportDocument[d].ticket_key, "openTicket") == 0) {
                    const dosipas_open_ticket_t *o = rt->transportDocument[d].openTicket;
                    TEST_ASSERT_NOT_NULL(o);
                    const tj_value_t *ov = tj_get(tkt, "value");
                    const tj_value_t *vr = tj_get(ov, "validRegion");
                    TEST_ASSERT_EQUAL_UINT(vr ? vr->count : 0, o->validRegion_count);
                    const tj_value_t *cc = tj_get(ov, "classCode");
                    if (cc) TEST_ASSERT_EQUAL_STRING(cc->str, o->classCode);
                    const tj_value_t *price = tj_get(ov, "price");
                    TEST_ASSERT_EQUAL(price != NULL, o->has_price);
                    if (price) TEST_ASSERT_EQUAL_INT64(price->inum, o->price);
                }
            }
            const tj_value_t *trav = tj_get(dec, "travelerDetail");
            TEST_ASSERT_EQUAL(trav != NULL, rt->travelerDetail != NULL);
            if (trav) {
                const tj_value_t *tl = tj_get(trav, "traveler");
                TEST_ASSERT_EQUAL_UINT(tl ? tl->count : 0, rt->travelerDetail->traveler_count);
                for (size_t p = 0; tl && p < tl->count; p++) {
                    const tj_value_t *fn = tj_get(tj_at(tl, p), "firstName");
                    if (fn) TEST_ASSERT_EQUAL_STRING(fn->str, rt->travelerDetail->traveler[p].firstName);
                }
            }
        }
        const tj_value_t *l2 = tj_get(tj_get(tk, "level2SignedData"), "level2Data");
        TEST_ASSERT_EQUAL(l2 != NULL, t->level2Data != NULL);
        if (l2) {
            TEST_ASSERT_EQUAL_STRING(tj_get(l2, "dataFormat")->str, t->level2Data->dataFormat);
            const tj_value_t *dec = tj_get(l2, "decoded");
            TEST_ASSERT_EQUAL(dec != NULL, (t->level2Data->fdc1 || t->level2Data->intercode) != 0);
        }
        tj_free(g);
    }
}

/* ------------------------------------------------------------------------- */
/* times: time helpers                                                       */
/* ------------------------------------------------------------------------- */

static void check_time(const char *fixture, const char *what, const tj_value_t *expected, bool have, int64_t got) {
    char msg[160];
    snprintf(msg, sizeof msg, "%s %s", fixture, what);
    bool exp_have = expected && expected->kind == TJ_NUMBER;
    TEST_ASSERT_EQUAL_MESSAGE(exp_have, have, msg);
    if (exp_have) TEST_ASSERT_EQUAL_INT64_MESSAGE(expected->inum, got, msg);
}

static void test_time_helpers(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        int64_t v = 0;
        bool have = dosipas_issuing_time(t, &v);
        check_time(FIXTURES[i].name, "issuingTime", tj_get(g, "issuingTime"), have, v);
        have = dosipas_end_of_validity_time(t, &v);
        check_time(FIXTURES[i].name, "endOfValidityTime", tj_get(g, "endOfValidityTime"), have, v);
        have = dosipas_dynamic_content_time(t, &v);
        check_time(FIXTURES[i].name, "dynamicContentTime", tj_get(g, "dynamicContentTime"), have, v);

        const tj_value_t *w = tj_get(g, "openTicketValidityWindow");
        const dosipas_rail_ticket_t *rt = dosipas_first_rail_ticket(t);
        const dosipas_open_ticket_t *open = NULL;
        for (size_t d = 0; rt && d < rt->transportDocument_count; d++)
            if (rt->transportDocument[d].openTicket) { open = rt->transportDocument[d].openTicket; break; }
        int64_t from = 0, until = 0;
        have = open && rt->issuingDetail && dosipas_open_ticket_validity_window(open, rt->issuingDetail, &from, &until);
        TEST_ASSERT_EQUAL_MESSAGE(w && w->kind == TJ_OBJECT, have, FIXTURES[i].name);
        if (have) {
            TEST_ASSERT_EQUAL_INT64_MESSAGE(tj_get(w, "validFrom")->inum, from, FIXTURES[i].name);
            TEST_ASSERT_EQUAL_INT64_MESSAGE(tj_get(w, "validUntil")->inum, until, FIXTURES[i].name);
        }
        tj_free(g);
    }
    /* Date.UTC semantics: day-of-year overflow rolls into the next year, 2020-04-30T16:35Z. */
    TEST_ASSERT_EQUAL_INT64(1588264500, dosipas_utc_from_day_of_year(2020, 121, 995, 0));
    TEST_ASSERT_EQUAL_INT64(dosipas_utc_from_day_of_year(2025, 1, 0, 0), dosipas_utc_from_day_of_year(2024, 367, 0, 0));
}

/* ------------------------------------------------------------------------- */
/* signed: signed byte extraction                                            */
/* ------------------------------------------------------------------------- */

static void test_signed_bytes(void) {
    setup_buffers();
    static uint8_t expected[4096], got[4096];
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        const tj_value_t *sb = tj_get(g, "signedBytes");
        size_t n = 0;
        size_t en = hex_to_bytes(tj_get(sb, "level1")->str, expected, sizeof expected);
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_level1_signed_bytes(FIXTURES[i].payload, FIXTURES[i].payload_len, t, got, sizeof got, &n));
        TEST_ASSERT_EQUAL_UINT_MESSAGE(en, n, FIXTURES[i].name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, got, en, FIXTURES[i].name);
        en = hex_to_bytes(tj_get(sb, "level2")->str, expected, sizeof expected);
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_level2_signed_bytes(FIXTURES[i].payload, FIXTURES[i].payload_len, t, got, sizeof got, &n));
        TEST_ASSERT_EQUAL_UINT_MESSAGE(en, n, FIXTURES[i].name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected, got, en, FIXTURES[i].name);
        /* Too small a buffer reports the size and does not write past it. */
        got[0] = 0xaa;
        TEST_ASSERT_EQUAL(DOSIPAS_ERR_SMALL_BUFFER, dosipas_level2_signed_bytes(FIXTURES[i].payload, FIXTURES[i].payload_len, t, got, 1, &n));
        TEST_ASSERT_EQUAL_UINT(en, n);
        TEST_ASSERT_EQUAL_HEX8(0xaa, got[0]);
        tj_free(g);
    }
}

/* ------------------------------------------------------------------------- */
/* robustness: truncation, bit flips, tiny arenas                            */
/* ------------------------------------------------------------------------- */

static void exercise(const uint8_t *payload, size_t len) {
    dosipas_ticket_t *t = NULL;
    dosipas_arena_reset(&g_arena);
    dosipas_err_t err = dosipas_decode(payload, len, &g_arena, &t);
    if (err == DOSIPAS_OK) {
        TEST_ASSERT_NOT_NULL(t);
        size_t needed = 0;
        dosipas_json_write(t, g_json, 2048, &needed); /* small cap: exercises the truncation path too */
        int64_t v;
        dosipas_issuing_time(t, &v);
        dosipas_end_of_validity_time(t, &v);
        dosipas_dynamic_content_time(t, &v);
        char lines[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
        dosipas_summary(t, NULL, lines, DOSIPAS_SUMMARY_MAX_LINES);
        uint8_t sb[8];
        size_t n;
        dosipas_level1_signed_bytes(payload, len, t, sb, sizeof sb, &n);
        dosipas_level2_signed_bytes(payload, len, t, sb, sizeof sb, &n);
    } else {
        TEST_ASSERT_NULL(t);
        TEST_ASSERT_EQUAL(err, g_arena.fail_code);
        TEST_ASSERT_TRUE(g_arena.fail_bit <= len * 8);
    }
    TEST_ASSERT_TRUE(g_arena.used <= g_arena.cap);
}

static void test_truncation(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        for (size_t len = 1; len <= FIXTURES[i].payload_len; len++) exercise(FIXTURES[i].payload, len);
        TEST_ASSERT_EQUAL(DOSIPAS_ERR_ARG, dosipas_decode(FIXTURES[i].payload, 0, &g_arena, NULL));
    }
}

static void test_bit_flips(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        size_t len = FIXTURES[i].payload_len;
        memcpy(g_scratch, FIXTURES[i].payload, len);
        for (size_t bit = 0; bit < len * 8; bit++) {
            g_scratch[bit >> 3] ^= (uint8_t)(0x80u >> (bit & 7));
            exercise(g_scratch, len);
            g_scratch[bit >> 3] ^= (uint8_t)(0x80u >> (bit & 7));
        }
    }
}

static void test_small_arena(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        size_t full;
        {
            dosipas_arena_reset(&g_arena);
            dosipas_ticket_t *t = NULL;
            TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_decode(FIXTURES[i].payload, FIXTURES[i].payload_len, &g_arena, &t));
            full = g_arena.used;
        }
        /* Every arena smaller than what the ticket needs must fail cleanly with ARENA_FULL. */
        for (size_t cap = 0; cap < full; cap += 8) {
            dosipas_arena_t small;
            dosipas_arena_init(&small, g_arena_buf, cap);
            dosipas_ticket_t *t = NULL;
            dosipas_err_t err = dosipas_decode(FIXTURES[i].payload, FIXTURES[i].payload_len, &small, &t);
            TEST_ASSERT_EQUAL_MESSAGE(DOSIPAS_ERR_ARENA_FULL, err, FIXTURES[i].name);
            TEST_ASSERT_NULL(t);
            TEST_ASSERT_TRUE(small.used <= small.cap);
        }
        /* Unaligned arena start works. */
        dosipas_arena_t odd;
        dosipas_arena_init(&odd, g_arena_buf + 3, ARENA_SIZE - 3);
        dosipas_ticket_t *t = NULL;
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_decode(FIXTURES[i].payload, FIXTURES[i].payload_len, &odd, &t));
        TEST_ASSERT_EQUAL_UINT(full, odd.used);
    }
}

static void test_bad_inputs(void) {
    setup_buffers();
    dosipas_ticket_t *t = NULL;
    static const uint8_t not_u[] = {0x01, 0x55, 0x22, 0x00, 0x00}; /* format "UX"-ish garbage */
    TEST_ASSERT_EQUAL(DOSIPAS_ERR_ARG, dosipas_decode(NULL, 10, &g_arena, &t));
    TEST_ASSERT_EQUAL(DOSIPAS_ERR_ARG, dosipas_decode(not_u, sizeof not_u, NULL, &t));
    TEST_ASSERT_EQUAL(DOSIPAS_ERR_ARG, dosipas_decode(not_u, sizeof not_u, &g_arena, NULL));
    /* "U3": presence bit 0, length 2 (0 + 7 bits), 'U' (1010101) '3' (0110011) -> 00000001 01010101 0110011x */
    static const uint8_t u3[] = {0x01, 0x55, 0x66, 0x00, 0x00, 0x00};
    dosipas_arena_reset(&g_arena);
    TEST_ASSERT_EQUAL(DOSIPAS_ERR_HEADER_VERSION, dosipas_decode(u3, sizeof u3, &g_arena, &t));
    /* "X1" -> unknown format */
    static const uint8_t x1[] = {0x01, 0x58, 0x62, 0x00, 0x00, 0x00}; /* 'X' (1011000) '1' (0110001) */
    dosipas_arena_reset(&g_arena);
    TEST_ASSERT_EQUAL(DOSIPAS_ERR_FORMAT, dosipas_decode(x1, sizeof x1, &g_arena, &t));
    /* FCB with a corrupted body: header decodes, `decoded` is NULL with an error, like dosipas-ts. */
    size_t len = FIXTURES[0].payload_len;
    memcpy(g_scratch, FIXTURES[0].payload, len);
    dosipas_arena_reset(&g_arena);
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_decode(g_scratch, len, &g_arena, &t));
    const dosipas_data_entry_t *e = &t->level1Data.dataSequence[0];
    TEST_ASSERT_NOT_NULL(e->decoded);
    /* Overwrite the FCB payload bytes with 0xff inside the barcode. */
    uint32_t off = e->decoded->value->bit_offset; /* this is relative to the FCB data, so locate the data in the payload */
    (void)off;
    const dosipas_value_t *l1 = dosipas_value_field(dosipas_value_field(t->header, "level2SignedData"), "level1Data");
    const dosipas_value_t *ds = dosipas_value_field(l1, "dataSequence");
    const dosipas_value_t *data = dosipas_value_field(dosipas_value_item(ds, 0), "data");
    TEST_ASSERT_NOT_NULL(data);
    /* Fill the first bytes of the OCTET STRING contents (after its length determinant). */
    uint32_t content_bit = data->bit_offset + 8; /* length < 128 -> 8-bit determinant */
    for (int k = 0; k < 16; k++) g_scratch[(content_bit + 8 * k) >> 3] = 0xff;
    dosipas_arena_reset(&g_arena);
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_decode(g_scratch, len, &g_arena, &t));
    TEST_ASSERT_NULL(t->level1Data.dataSequence[0].decoded);
    TEST_ASSERT_NOT_EQUAL(DOSIPAS_OK, t->level1Data.dataSequence[0].decode_error);
}

/* ------------------------------------------------------------------------- */
/* verify: signatures                                                        */
/* ------------------------------------------------------------------------- */

static bool verification_available(void) {
    bool valid = false;
    char err[64];
    static const uint8_t dummy[1] = {0};
    return dosipas_ecdsa_verify("P-256", "SHA-256", dummy, 1, dummy, 1, dummy, 1, &valid, err, sizeof err) !=
           DOSIPAS_ERR_UNSUPPORTED;
}

static void test_verify_level2(void) {
    setup_buffers();
    if (!verification_available()) TEST_IGNORE_MESSAGE("built without mbedTLS");
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        const tj_value_t *exp = tj_get(g, "level2Verification");
        dosipas_verify_result_t r;
        dosipas_err_t err = dosipas_verify_level2(FIXTURES[i].payload, FIXTURES[i].payload_len, t, NULL, &g_arena, &r);
        TEST_ASSERT_EQUAL_MESSAGE(DOSIPAS_OK, err, FIXTURES[i].name);
        TEST_ASSERT_EQUAL_MESSAGE(tj_get(exp, "valid")->b, r.valid, FIXTURES[i].name);
        const tj_value_t *eerr = tj_get(exp, "error");
        if (eerr && eerr->kind == TJ_STRING) {
            /* SAMPLE carries a raw r||s signature over a bogus key. dosipas-ts
             * rejects the format ("Invalid DER signature ..."); we accept raw
             * signatures, so the failure reason differs. Everything else matches. */
            if (strncmp(eerr->str, "Level 2 signature verification error", 36) != 0)
                TEST_ASSERT_EQUAL_STRING_MESSAGE(eerr->str, r.error, FIXTURES[i].name);
            else
                TEST_ASSERT_TRUE_MESSAGE(r.error[0] != 0, FIXTURES[i].name);
        } else {
            TEST_ASSERT_EQUAL_STRING_MESSAGE("", r.error, FIXTURES[i].name);
        }
        const tj_value_t *alg = tj_get(exp, "algorithm");
        if (alg && alg->kind == TJ_STRING) TEST_ASSERT_EQUAL_STRING_MESSAGE(alg->str, r.algorithm, FIXTURES[i].name);
        tj_free(g);
    }
}

static void test_verify_level1(void) {
    setup_buffers();
    if (!verification_available()) TEST_IGNORE_MESSAGE("built without mbedTLS");
    static uint8_t key[1024];
    int with_key = 0;
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        dosipas_ticket_t *t = decode_fixture(i);
        const tj_value_t *exps[2] = {tj_get(g, "level1Verification"), tj_get(g, "level1WithForeignKey")};
        for (int k = 0; k < 2; k++) {
            const tj_value_t *exp = exps[k];
            if (!exp || exp->kind != TJ_OBJECT) continue;
            if (k == 0) with_key++;
            size_t klen = hex_to_bytes(tj_get(exp, "publicKey")->str, key, sizeof key);
            dosipas_level1_key_t km = {key, klen, NULL, NULL};
            dosipas_verify_result_t r;
            dosipas_err_t err = dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r);
            TEST_ASSERT_EQUAL_MESSAGE(DOSIPAS_OK, err, FIXTURES[i].name);
            char msg[200];
            snprintf(msg, sizeof msg, "%s %s", FIXTURES[i].name, k ? "foreign key" : "registry key");
            TEST_ASSERT_EQUAL_MESSAGE(tj_get(exp, "valid")->b, r.valid, msg);
            const tj_value_t *eerr = tj_get(exp, "error");
            if (eerr && eerr->kind == TJ_STRING) TEST_ASSERT_EQUAL_STRING_MESSAGE(eerr->str, r.error, msg);
            else TEST_ASSERT_EQUAL_STRING_MESSAGE("", r.error, msg);
        }
        tj_free(g);
    }
    TEST_ASSERT_TRUE_MESSAGE(with_key >= 2, "expected at least two fixtures with a registry key");

    /* Issuer "IWN8" (Car Jaune): key recovered by dosipas-ts, OIDs supplied by the caller. */
    int configured = 0;
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        const tj_value_t *exp = tj_get(g, "level1WithConfiguredKey");
        if (exp && exp->kind == TJ_OBJECT) {
            dosipas_ticket_t *t = decode_fixture(i);
            size_t klen = hex_to_bytes(tj_get(exp, "publicKey")->str, key, sizeof key);
            dosipas_level1_key_entry_t table[2] = {
                {1187, NULL, 1, {key, klen, NULL, NULL}}, /* wrong issuer: must not match */
                {0, "IWN8", 1, {key, klen, tj_get(exp, "keyAlg")->str, tj_get(exp, "signingAlg")->str}},
            };
            const dosipas_level1_key_t *km = dosipas_level1_key_lookup(table, 2, t);
            TEST_ASSERT_NOT_NULL_MESSAGE(km, FIXTURES[i].name);
            TEST_ASSERT_EQUAL_PTR(&table[1].key, km);
            dosipas_verify_result_t r;
            TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, km, &g_arena, &r));
            TEST_ASSERT_EQUAL_MESSAGE(tj_get(exp, "valid")->b, r.valid, FIXTURES[i].name);
            TEST_ASSERT_EQUAL_STRING(tj_get(exp, "algorithm")->str, r.algorithm);
            TEST_ASSERT_EQUAL(DOSIPAS_ALG_SOURCE_CONFIGURED, r.algorithmSource);
            char lines[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
            int n = dosipas_summary_ex(t, &r, NULL, lines, DOSIPAS_SUMMARY_MAX_LINES);
            TEST_ASSERT_EQUAL_STRING(r.valid ? "L1 signature VALID" : "L1 signature INVALID", lines[n - 1]);
            TEST_ASSERT_NULL(dosipas_level1_key_lookup(table, 1, t));
            configured++;
        }
        tj_free(g);
    }
    TEST_ASSERT_EQUAL_MESSAGE(6, configured, "six Car Jaune tickets expected");

    /* Caller-supplied OIDs for a barcode without them (Car Jaune), and the mismatch rule. */
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        if (strcmp(FIXTURES[i].name, "CAR_JAUNE") != 0) continue;
        dosipas_ticket_t *t = decode_fixture(i);
        TEST_ASSERT_NULL(t->level1Data.level1SigningAlg);
        static const uint8_t fake_key[65] = {0x04};
        dosipas_level1_key_t km = {fake_key, sizeof fake_key, NULL, NULL};
        dosipas_verify_result_t r;
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r));
        TEST_ASSERT_FALSE(r.valid);
        TEST_ASSERT_EQUAL_STRING("Missing level 1 signing algorithm: the barcode has no level1SigningAlg OID and no signingAlg was configured.", r.error);
        km.signingAlg = "1.2.840.10045.4.3.2";
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r));
        TEST_ASSERT_EQUAL_STRING("Missing level 1 key algorithm: the barcode has no level1KeyAlg OID and no keyAlg was configured. ECDSA verification needs it to identify the curve.", r.error);
        km.keyAlg = "1.2.840.10045.3.1.7";
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r));
        TEST_ASSERT_FALSE(r.valid); /* fake key: invalid point */
        TEST_ASSERT_EQUAL_STRING("ECDSA P-256 with SHA-256", r.algorithm);
        TEST_ASSERT_EQUAL(DOSIPAS_ALG_SOURCE_CONFIGURED, r.algorithmSource);
        km.keyAlg = "not-an-oid";
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r));
        TEST_ASSERT_EQUAL_STRING_LEN("Invalid configured level 1 key algorithm: 'not-an-oid'.", r.error, 55);
    }
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        if (strcmp(FIXTURES[i].name, "SOLEA") != 0) continue;
        dosipas_ticket_t *t = decode_fixture(i);
        static const uint8_t fake_key[65] = {0x04};
        dosipas_level1_key_t km = {fake_key, sizeof fake_key, "1.3.132.0.34", NULL};
        dosipas_verify_result_t r;
        TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(FIXTURES[i].payload, FIXTURES[i].payload_len, t, &km, &g_arena, &r));
        TEST_ASSERT_EQUAL_STRING(
            "Level 1 key algorithm mismatch: the barcode declares '1.2.840.10045.3.1.7' (P-256) in level1KeyAlg, but "
            "'1.3.132.0.34' (P-384) was configured. Remove the override, or fix it to match the barcode.",
            r.error);
    }
}

/* Flip a bit inside the signed region: the signature must become invalid. */
static void test_tampered_payload(void) {
    setup_buffers();
    if (!verification_available()) TEST_IGNORE_MESSAGE("built without mbedTLS");
    static uint8_t key[1024];
    int checked = 0;
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        bool l2_valid = tj_get(tj_get(g, "level2Verification"), "valid")->b;
        const tj_value_t *l1 = tj_get(g, "level1Verification");
        bool l1_valid = l1 && l1->kind == TJ_OBJECT && tj_get(l1, "valid")->b;
        if (l2_valid || l1_valid) {
            size_t len = FIXTURES[i].payload_len;
            dosipas_ticket_t *t = decode_fixture(i);
            /* Flip a bit in the middle of level1Data (covered by both signatures). */
            uint32_t bit = t->level1Data.bit_offset + t->level1Data.bit_length / 2;
            memcpy(g_scratch, FIXTURES[i].payload, len);
            g_scratch[bit >> 3] ^= (uint8_t)(0x80u >> (bit & 7));
            dosipas_arena_reset(&g_arena);
            dosipas_ticket_t *tampered = NULL;
            if (dosipas_decode(g_scratch, len, &g_arena, &tampered) != DOSIPAS_OK) {
                /* The flip broke the structure: find a flip that still decodes. */
                for (bit = t->level1Data.bit_offset; bit < t->level1Data.bit_offset + t->level1Data.bit_length; bit++) {
                    memcpy(g_scratch, FIXTURES[i].payload, len);
                    g_scratch[bit >> 3] ^= (uint8_t)(0x80u >> (bit & 7));
                    dosipas_arena_reset(&g_arena);
                    if (dosipas_decode(g_scratch, len, &g_arena, &tampered) == DOSIPAS_OK) break;
                }
            }
            TEST_ASSERT_NOT_NULL_MESSAGE(tampered, "no decodable tampered variant");
            dosipas_verify_result_t r;
            if (l2_valid) {
                TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level2(g_scratch, len, tampered, NULL, &g_arena, &r));
                TEST_ASSERT_FALSE_MESSAGE(r.valid, FIXTURES[i].name);
                checked++;
            }
            if (l1_valid) {
                size_t klen = hex_to_bytes(tj_get(l1, "publicKey")->str, key, sizeof key);
                dosipas_level1_key_t km = {key, klen, NULL, NULL};
                TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_verify_level1(g_scratch, len, tampered, &km, &g_arena, &r));
                TEST_ASSERT_FALSE_MESSAGE(r.valid, FIXTURES[i].name);
                checked++;
            }
            /* A payload/ticket mismatch is refused. */
            TEST_ASSERT_EQUAL(DOSIPAS_ERR_ARG, dosipas_verify_level2(g_scratch, len - 1, tampered, NULL, &g_arena, &r));
        }
        tj_free(g);
    }
    TEST_ASSERT_TRUE(checked >= 6);
}

/* Compressed and uncompressed encodings of the same key verify the same signature. */
static void test_key_formats(void) {
    setup_buffers();
    if (!verification_available()) TEST_IGNORE_MESSAGE("built without mbedTLS");
    /* GRAND_EST carries a 91-byte SPKI key; the others a 33-byte compressed point. */
    int spki = 0, compressed = 0;
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        tj_value_t *g = golden(i);
        if (tj_get(tj_get(g, "level2Verification"), "valid")->b) {
            dosipas_ticket_t *t = decode_fixture(i);
            if (t->level1Data.level2PublicKey.len == 91) spki++;
            if (t->level1Data.level2PublicKey.len == 33) compressed++;
        }
        tj_free(g);
    }
    TEST_ASSERT_TRUE(spki >= 1);
    TEST_ASSERT_TRUE(compressed >= 3);
    /* Known P-256 vector: compressed and uncompressed forms of one key. */
    static const uint8_t pub_unc[65] = {
        0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61,
        0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56,
        0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
    uint8_t pub_comp[33];
    pub_comp[0] = (pub_unc[64] & 1) ? 0x03 : 0x02;
    memcpy(pub_comp + 1, pub_unc + 1, 32);
    /* RFC 6979 A.2.5 test vector: message "sample", SHA-256, raw r||s. */
    static const uint8_t sig[64] = {
        0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa,
        0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16, 0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1,
        0xb6, 0xe2, 0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};
    bool valid = false;
    char err[128];
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_ecdsa_verify("P-256", "SHA-256", pub_unc, 65, sig, 64, (const uint8_t *)"sample", 6, &valid, err, sizeof err));
    TEST_ASSERT_TRUE_MESSAGE(valid, err);
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_ecdsa_verify("P-256", "SHA-256", pub_comp, 33, sig, 64, (const uint8_t *)"sample", 6, &valid, err, sizeof err));
    TEST_ASSERT_TRUE_MESSAGE(valid, err);
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_ecdsa_verify("P-256", "SHA-256", pub_comp, 33, sig, 64, (const uint8_t *)"Sample", 6, &valid, err, sizeof err));
    TEST_ASSERT_FALSE(valid);
    /* Wrong parity byte: a different (valid) point, so the signature does not verify. */
    pub_comp[0] ^= 0x01;
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_ecdsa_verify("P-256", "SHA-256", pub_comp, 33, sig, 64, (const uint8_t *)"sample", 6, &valid, err, sizeof err));
    TEST_ASSERT_FALSE(valid);
    /* x not on the curve. */
    pub_comp[0] ^= 0x01;
    pub_comp[1] ^= 0xff;
    TEST_ASSERT_EQUAL(DOSIPAS_OK, dosipas_ecdsa_verify("P-256", "SHA-256", pub_comp, 33, sig, 64, (const uint8_t *)"sample", 6, &valid, err, sizeof err));
    TEST_ASSERT_FALSE(valid);
}

/* ------------------------------------------------------------------------- */
/* summary                                                                   */
/* ------------------------------------------------------------------------- */

static void test_summary(void) {
    setup_buffers();
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        dosipas_ticket_t *t = decode_fixture(i);
        char lines[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
        int n = dosipas_summary(t, NULL, lines, DOSIPAS_SUMMARY_MAX_LINES);
        TEST_ASSERT_TRUE(n >= 3 && n <= DOSIPAS_SUMMARY_MAX_LINES);
        for (int k = 0; k < n; k++) {
            TEST_ASSERT_TRUE_MESSAGE(strlen(lines[k]) <= DOSIPAS_SUMMARY_COLUMNS, lines[k]);
            for (const char *p = lines[k]; *p; p++) TEST_ASSERT_TRUE_MESSAGE(*p >= 0x20 && *p <= 0x7e, lines[k]);
        }
        TEST_ASSERT_EQUAL_STRING_LEN(t->format, lines[0], 2);
        if (t->level2Signature.ptr) {
            TEST_ASSERT_EQUAL_STRING("L2 signature not verifiable", lines[n - 1]);
            dosipas_verify_result_t r = {true, "", "", DOSIPAS_ALG_SOURCE_BARCODE};
            n = dosipas_summary(t, &r, lines, DOSIPAS_SUMMARY_MAX_LINES);
            TEST_ASSERT_EQUAL_STRING("L2 signature VALID", lines[n - 1]);
            r.valid = false;
            n = dosipas_summary(t, &r, lines, DOSIPAS_SUMMARY_MAX_LINES);
            TEST_ASSERT_EQUAL_STRING("L2 signature INVALID", lines[n - 1]);
        } else {
            TEST_ASSERT_EQUAL_STRING("L1 signed, key not checked", lines[n - 1]);
        }
    }
}

/* ------------------------------------------------------------------------- */
/* metrics: arena / heap / stack / time per fixture                          */
/* ------------------------------------------------------------------------- */

static void test_metrics(void) {
    setup_buffers();
    printf("\n%-18s %5s %7s %7s %9s %9s %9s %9s\n", "fixture", "bytes", "arena", "heapmin", "stackHWM", "decode_us", "json_us", "verify_us");
    size_t max_peak = 0;
    for (size_t i = 0; i < FIXTURE_COUNT; i++) {
        dosipas_arena_reset(&g_arena);
        g_arena.peak = 0;
        size_t heap_before = FREE_HEAP();
        (void)heap_before;
        int64_t t0 = NOW_US();
        dosipas_ticket_t *t = NULL;
        dosipas_err_t err = dosipas_decode(FIXTURES[i].payload, FIXTURES[i].payload_len, &g_arena, &t);
        int64_t t1 = NOW_US();
        TEST_ASSERT_EQUAL(DOSIPAS_OK, err);
        size_t needed = 0;
        dosipas_json_write(t, g_json, JSON_CAP, &needed);
        int64_t t2 = NOW_US();
        int64_t verify_us = -1;
        if (t->level2Signature.ptr && verification_available()) {
            dosipas_verify_result_t r;
            int64_t v0 = NOW_US();
            dosipas_verify_level2(FIXTURES[i].payload, FIXTURES[i].payload_len, t, NULL, &g_arena, &r);
            verify_us = NOW_US() - v0;
        }
        size_t heap_min = MIN_FREE_HEAP();
        size_t stack_hwm = 0;
#ifdef ARDUINO
        stack_hwm = uxTaskGetStackHighWaterMark(NULL);
#endif
        if (g_arena.peak > max_peak) max_peak = g_arena.peak;
        printf("%-18s %5u %7u %7u %9u %9lld %9lld %9lld\n", FIXTURES[i].name, (unsigned)FIXTURES[i].payload_len,
               (unsigned)g_arena.peak, (unsigned)heap_min, (unsigned)stack_hwm, (long long)(t1 - t0), (long long)(t2 - t1),
               (long long)verify_us);
    }
    printf("max arena peak %u B of %u B\n", (unsigned)max_peak, (unsigned)ARENA_SIZE);
    TEST_ASSERT_TRUE_MESSAGE(max_peak * 4 <= ARENA_SIZE * 3, "arena margin below 25%");
}

/* ------------------------------------------------------------------------- */
/* Runner                                                                    */
/* ------------------------------------------------------------------------- */

void setUp(void) {}
void tearDown(void) {}

typedef struct {
    const char *group;
    void (*fn)(void);
    const char *name;
} test_t;

#define T(group, fn) {group, fn, #fn}
static const test_t TESTS[] = {
    T("golden", test_golden_json),
    T("golden", test_typed_view),
    T("times", test_time_helpers),
    T("signed", test_signed_bytes),
    T("robustness", test_truncation),
    T("robustness", test_bit_flips),
    T("robustness", test_small_arena),
    T("robustness", test_bad_inputs),
    T("verify", test_verify_level2),
    T("verify", test_verify_level1),
    T("verify", test_tampered_payload),
    T("verify", test_key_formats),
    T("summary", test_summary),
    T("metrics", test_metrics),
};

static int run_groups(int argc, const char **argv) {
    UNITY_BEGIN();
    for (size_t i = 0; i < sizeof TESTS / sizeof *TESTS; i++) {
        bool selected = argc <= 1;
        for (int a = 1; a < argc && !selected; a++) selected = strcmp(argv[a], TESTS[i].group) == 0 || strcmp(argv[a], TESTS[i].name) == 0;
        if (selected) UnityDefaultTestRun(TESTS[i].fn, TESTS[i].name, __LINE__);
    }
    return UNITY_END();
}

#ifdef ARDUINO
void setup() {
    delay(2000);
    printf("dosipas-c tests, fixtures from %s, free heap %u B\n", FIXTURES_DOSIPAS_TS_VERSION, (unsigned)FREE_HEAP());
    run_groups(0, NULL);
}
void loop() { delay(1000); }
#else
int main(int argc, char **argv) {
    printf("dosipas-c tests, fixtures from %s\n", FIXTURES_DOSIPAS_TS_VERSION);
    return run_groups(argc, (const char **)argv);
}
#endif
