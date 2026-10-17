/*
 * dosipas-c: thin C++ wrapper for Arduino sketches (header only).
 *
 *   #include <DosipasDecoder.h>
 *   static uint8_t arenaBuf[DOSIPAS_RECOMMENDED_ARENA_SIZE];
 *   DosipasDecoder dosipas(arenaBuf, sizeof arenaBuf);
 *   if (dosipas.decode(payload, len)) {
 *     const dosipas_ticket_t *t = dosipas.ticket();
 *     dosipas.verifyLevel2();                      // optional, needs mbedTLS
 *     Serial.println(dosipas.json());              // same output as dosipas-ts
 *     for (int i = 0; i < dosipas.summary(); i++) Serial.println(dosipas.summaryLine(i));
 *   }
 *
 * The wrapper owns no memory besides the arena you give it; the decoded ticket
 * lives in that arena until the next decode(). (The file is not named
 * Dosipas.h because that collides with dosipas.h on case-insensitive file
 * systems.)
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef DOSIPAS_DECODER_HPP
#define DOSIPAS_DECODER_HPP

#include <stdlib.h>

#include "dosipas.h"
#include "dosipas_json.h"
#include "dosipas_summary.h"
#include "dosipas_verify.h"

#ifdef ARDUINO
#include <Arduino.h>
#endif

class DosipasDecoder {
public:
    DosipasDecoder(void *arenaBuffer, size_t arenaSize)
        : ticket_(nullptr), level2Checked_(false), lines_(0), payload_(nullptr), payloadLen_(0) {
        dosipas_arena_init(&arena_, arenaBuffer, arenaSize);
        level2_.valid = false;
        level2_.error[0] = 0;
        level2_.algorithm[0] = 0;
        level2_.algorithmSource = DOSIPAS_ALG_SOURCE_NONE;
    }

    /* Decode a payload. The buffer must stay valid until verifyLevel2() /
     * verifyLevel1() are done (the ticket itself does not reference it). */
    bool decode(const uint8_t *payload, size_t len) {
        dosipas_arena_reset(&arena_);
        ticket_ = nullptr;
        level2Checked_ = false;
        lines_ = 0;
        payload_ = payload;
        payloadLen_ = len;
        return dosipas_decode(payload, len, &arena_, &ticket_) == DOSIPAS_OK;
    }

    const dosipas_ticket_t *ticket() const { return ticket_; }
    dosipas_err_t error() const { return arena_.fail_code; }
    const char *errorString() const { return dosipas_strerror(arena_.fail_code); }
    uint32_t errorBit() const { return arena_.fail_bit; }
    size_t arenaUsed() const { return arena_.used; }
    size_t arenaPeak() const { return arena_.peak; }
    dosipas_arena_t *arena() { return &arena_; }

    /* Level 2 verification with the key embedded in the barcode. */
    bool verifyLevel2(const dosipas_level2_algorithms_t *algorithms = nullptr) {
        if (!ticket_) return false;
        if (dosipas_verify_level2(payload_, payloadLen_, ticket_, algorithms, &arena_, &level2_) != DOSIPAS_OK) return false;
        level2Checked_ = true;
        return level2_.valid;
    }
    const dosipas_verify_result_t *level2Result() const { return level2Checked_ ? &level2_ : nullptr; }

    /* Level 1 verification with a caller-supplied key. */
    bool verifyLevel1(const dosipas_level1_key_t &key, dosipas_verify_result_t *out) {
        if (!ticket_) return false;
        return dosipas_verify_level1(payload_, payloadLen_, ticket_, &key, &arena_, out) == DOSIPAS_OK && out->valid;
    }

    /* Summary lines for a 33x14 display. Returns the line count. */
    int summary() {
        lines_ = ticket_ ? dosipas_summary(ticket_, level2Checked_ ? &level2_ : nullptr, summary_, DOSIPAS_SUMMARY_MAX_LINES) : 0;
        return lines_;
    }
    const char *summaryLine(int i) const { return (i >= 0 && i < lines_) ? summary_[i] : ""; }

    /* JSON into a caller buffer (snprintf semantics: returns the full length). */
    size_t json(char *buf, size_t cap) const {
        size_t needed = 0;
        if (ticket_) dosipas_json_write(ticket_, buf, cap, &needed);
        else if (cap) buf[0] = 0;
        return needed;
    }

#ifdef ARDUINO
    String json() const {
        if (!ticket_) return String();
        size_t needed = 0;
        dosipas_json_write(ticket_, nullptr, 0, &needed);
        char *tmp = (char *)malloc(needed + 1);
        if (!tmp) return String();
        dosipas_json_write(ticket_, tmp, needed + 1, &needed);
        String s(tmp);
        free(tmp);
        return s;
    }
#endif

private:
    dosipas_arena_t arena_;
    dosipas_ticket_t *ticket_;
    dosipas_verify_result_t level2_;
    bool level2Checked_;
    char summary_[DOSIPAS_SUMMARY_MAX_LINES][DOSIPAS_SUMMARY_LINE_SIZE];
    int lines_;
    const uint8_t *payload_;
    size_t payloadLen_;
};

#endif /* DOSIPAS_DECODER_HPP */
