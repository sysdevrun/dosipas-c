# dosipas-c

Decode and verify DOSIPAS tickets (UIC barcodes with Intercode 6 extensions) in
C99, for the ESP32 and for desktop hosts. Reference implementation and source
of truth for behaviour: [dosipas-ts](https://github.com/sysdevrun/dosipas-ts)
**4.1.0** (the golden files in `fixtures/` were produced by that version).

Status: **work in progress**. Host decoding, JSON parity, time helpers, signed
bytes, level 1/2 verification and robustness tests are done and green on macOS.
Not yet done: ESP32 on-device test run with measurements, flash size numbers,
PlatformIO native test confirmation, fuzz run results. See "Remaining work".

## Approach

A **table-driven UPER decoder**. `tools/gen_schema_tables.mjs` turns the
dosipas-ts JSON schemas into `src/dosipas_schema_tables.c`: 12,363 schema nodes
collapse into 227 shared 16-byte nodes plus field/alternative/enum/string
tables, **20.5 KiB** of flash for header v1/v2, FCB1/2/3, Intercode 6 and FDC1
together. One small runtime (`src/dosipas_decode.c`, about 7 KB on x86-64 at
`-Os`) decodes any of them into a generic value tree in a caller-provided arena;
`src/dosipas_ticket.c` binds a typed view mirroring the dosipas-ts types.

Why not asn1c: the existing prototype compiled for xtensa at `-Os` measures
110 KB text + 59 KB data for the FCB3 types alone, 67 KB for the header, plus a
38 KB (PER-only) to 80 KB runtime. Three FCB versions would exceed 400 KB,
malloc per node, and Intercode/FDC1 were not covered.

Regenerate tables and goldens (needs Node; `tools/package.json` pins dosipas-ts 4.1.0):

```
cd tools && npm install && cd ..
node tools/gen_schema_tables.mjs
node tools/gen_golden.mjs --dosipas-ts ~/wd/dosipas/dosipas-ts   # checkout needed once for Car Jaune + key XML
node tools/embed_fixtures.mjs
```

## API (see `src/dosipas.h`)

```c
static uint8_t buf[DOSIPAS_RECOMMENDED_ARENA_SIZE];   /* 16 KB */
dosipas_arena_t arena; dosipas_arena_init(&arena, buf, sizeof buf);
dosipas_ticket_t *t;
dosipas_err_t err = dosipas_decode(payload, len, &arena, &t);  /* arena.fail_bit on error */
```

- `dosipas_ticket_t`: `format`, `level1Data` (typed, with `bit_offset`/`bit_length`
  of the signed node), `level1Signature`, `level2Data` (FDC1 / Intercode `_RICS.ID1`
  typed), `level2Signature`, `level2SignedData_bit_*`, and the generic `header` tree.
  Each `dataSequence` entry carries `decoded` (FCB1/2/3 typed rail ticket:
  issuingDetail + intercodeIssuing, travelerDetail, transportDocument with typed
  openTicket, controlDetail) and the generic tree for everything else.
- `dosipas_level1_signed_bytes` / `dosipas_level2_signed_bytes`: exact bytes
  covered by each signature (bit range copied from the payload, byte-aligned,
  zero-padded), identical to dosipas-ts `extractTicket`.
- Time helpers: `dosipas_issuing_time`, `dosipas_end_of_validity_time`,
  `dosipas_dynamic_content_time`, `dosipas_open_ticket_validity_window` (Unix
  seconds, UTC, no device clock).
- `dosipas_json.h`: `dosipas_json_write` (snprintf semantics), output equal to
  dosipas-ts `decodeTicket` once parsed (bytes as lowercase hex).
- `dosipas_verify.h`: `dosipas_verify_level2` (key in the barcode),
  `dosipas_verify_level1` (caller key: raw point, SPKI DER or X.509), mbedTLS
  ECDSA P-256/384/521 with SHA-256/384/512; compressed points decompressed with
  `mbedtls_mpi`; DSA/RSA reported unsupported with the dosipas-ts error text.
  Needs `DOSIPAS_WITH_MBEDTLS=1` (automatic on ESP32). Works with mbedTLS 2.28
  and 3.6 (public API only, tested against v2.28.10 and v3.6.4).
- `dosipas_summary.h`: 33x14 ASCII lines for the e-paper, same content as
  `tools/ticket_summary.mjs` in grow-GM69Pro.
- `DosipasDecoder.h`: header-only C++ wrapper for Arduino.

Divergences from dosipas-ts (documented, tested): raw `r||s` signatures are
accepted in addition to DER (dosipas-ts rejects them); the error text for a
malformed public key point is more specific than dosipas-ts's generic
"verification failed". `valid` always matches.

## Measurements (host, macOS arm64; ESP32 numbers still to be taken)

Arena peak per fixture with the 16 KB recommended arena:

| Fixture | Payload | Arena peak |
|---|---|---|
| CAR_JAUNE (x6) | 154-156 B | 3072-3080 B |
| SAMPLE | 307 B | 5152 B |
| BUS_ARDECHE / BUS_AIN / DROME_BUS | 351-357 B | 5080-5176 B |
| SOLEA | 412 B | 5808 B |
| GRAND_EST_U1_FCB3 | 450 B | 5832 B |
| SNCF_TER | 212 B | 6040 B |
| CTS | 424 B | 6328 B |

Host decode 1-3 us, JSON 1-3 us, level 2 verify about 0.8 ms per fixture (release).

## Tests

```
cmake -S . -B build -DDOSIPAS_SANITIZE=ON && cmake --build build && ctest --test-dir build
pio test -e native                      # fetches/builds mbedTLS 3.6.4 into .deps/ on first run
MBEDTLS_TAG=v2.28.10 pio test -e native
pio test -e esp32dev                    # prints arena/heap/stack/time per fixture
fuzz/run.sh 120                         # libFuzzer, needs Homebrew LLVM
```

Groups: golden (JSON equality with the path of the first difference, typed
view), times, signed, robustness (every truncation length, every bit flip,
every arena size below the need, bad formats), verify (level 2 on every
fixture, level 1 with registry keys for SOLEA and CTS plus error paths, tampered
payloads, key formats), summary, metrics. All 14 pass under ASan+UBSan.

Privacy: only the public dosipas-ts fixtures are committed; never add a
personal ticket to fixtures, tests, examples or the fuzz corpus.

## Packaging

`library.json` (PlatformIO), `library.properties` (Arduino, public headers live
in `src/`, `include/` holds forwarders), `idf_component.yml` + `CMakeLists.txt`
(ESP-IDF component). Example: `examples/GM69ProDecode` (UART2 RX 33 / TX 32,
9600 8N1, 4096 B RX buffer, mute then European double-byte charset).

## Remaining work

1. Run `pio test -e esp32dev` on the board and record arena/heap/stack/time.
2. Record ESP32 flash cost: `xtensa-esp32-elf-size` on the library objects of
   the example build, with and without `dosipas_verify.c`.
3. Confirm `pio test -e native`, the example build and the fuzz run (they were
   launched; logs in the session scratchpad were not yet reviewed).
4. Fill the ESP32 numbers into this README.

License: MIT.
