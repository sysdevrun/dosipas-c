/*
 * GM69ProDecode: read Aztec scans from a GM69Pro barcode module on UART2,
 * decode the DOSIPAS ticket on the ESP32 and print the e-paper summary lines.
 *
 * Wiring (ESP32-WROOM-32E): GM69Pro TX -> GPIO33 (RX2), GM69Pro RX -> GPIO32 (TX2),
 * 9600 baud 8N1. See README.md for the scanner settings that are required for
 * binary payloads (European double-byte charset) and the mute command.
 *
 * A scan ends after about 50 ms without new bytes. The UART RX buffer is set
 * to 4096 bytes so a whole payload fits even if the loop is busy.
 *
 * SPDX-License-Identifier: MIT
 */
#include <Arduino.h>
#include <DosipasDecoder.h>

static const int SCANNER_RX = 33;  /* ESP32 pin wired to the GM69Pro TX */
static const int SCANNER_TX = 32;  /* ESP32 pin wired to the GM69Pro RX */
static const uint32_t SCAN_GAP_MS = 50;
static const size_t MAX_PAYLOAD = 2048;

/* Configuration commands (see the GM69Pro user manual). */
static const uint8_t CMD_MUTE[] = {0x16, 0x57, 0x61, 0x5A, 0x61, 0x53, 0x61, 0x2E};
static const uint8_t CMD_CHARSET_EUROPEAN_DOUBLE_BYTE[] = {0x16, 0x4F, 0x64, 0x50, 0x62, 0x4E, 0x62, 0x63, 0x2E};

static HardwareSerial scanner(2);
static uint8_t payload[MAX_PAYLOAD];
static size_t payloadLen = 0;
static uint32_t lastByteMs = 0;

/* 16 KB decodes every dosipas-ts fixture with more than 2x margin (peak 6.3 KB). */
static uint8_t arenaBuf[DOSIPAS_RECOMMENDED_ARENA_SIZE];
static DosipasDecoder dosipas(arenaBuf, sizeof arenaBuf);

static void sendCommand(const uint8_t *cmd, size_t len) {
    scanner.write(cmd, len);
    scanner.flush();
    delay(100);
    while (scanner.available()) scanner.read(); /* drop the ACK */
}

void setup() {
    Serial.begin(115200);
    scanner.setRxBufferSize(4096);
    scanner.begin(9600, SERIAL_8N1, SCANNER_RX, SCANNER_TX);
    delay(500);
    /* Always mute first: the module beeps on every configuration command. */
    sendCommand(CMD_MUTE, sizeof CMD_MUTE);
    sendCommand(CMD_CHARSET_EUROPEAN_DOUBLE_BYTE, sizeof CMD_CHARSET_EUROPEAN_DOUBLE_BYTE);
    Serial.println("GM69Pro ready, scan a DOSIPAS ticket");
}

static void handleScan(const uint8_t *data, size_t len) {
    uint32_t t0 = micros();
    bool ok = dosipas.decode(data, len);
    uint32_t decodeUs = micros() - t0;
    if (!ok) {
        Serial.printf("not a DOSIPAS ticket: %s at bit %u (%u bytes)\n", dosipas.errorString(), dosipas.errorBit(), (unsigned)len);
        return;
    }
    t0 = micros();
    bool l2 = dosipas.ticket()->level2Signature.ptr ? dosipas.verifyLevel2() : false;
    uint32_t verifyUs = micros() - t0;

    int n = dosipas.summary();
    Serial.println("---------------------------------");
    for (int i = 0; i < n; i++) Serial.println(dosipas.summaryLine(i));
    Serial.println("---------------------------------");
    Serial.printf("decode %u us, verify %u us (%s), arena %u B, stack high-water %u B, free heap %u B\n", decodeUs, verifyUs,
                  dosipas.level2Result() ? (l2 ? "valid" : dosipas.level2Result()->error) : "no level 2 signature",
                  (unsigned)dosipas.arenaPeak(), (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)ESP.getFreeHeap());
    /* Full JSON, identical to dosipas-ts decodeTicket(): */
    Serial.println(dosipas.json());
}

void loop() {
    while (scanner.available()) {
        int c = scanner.read();
        if (payloadLen < MAX_PAYLOAD) payload[payloadLen++] = (uint8_t)c;
        lastByteMs = millis();
    }
    if (payloadLen && millis() - lastByteMs > SCAN_GAP_MS) {
        handleScan(payload, payloadLen);
        payloadLen = 0;
    }
}
