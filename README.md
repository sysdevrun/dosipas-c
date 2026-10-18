# dosipas-c

Decode and verify DOSIPAS tickets (UIC barcodes with Intercode 6 extensions) in
C99, for the ESP32 and for desktop hosts. Reference implementation and source
of truth for behaviour: [dosipas-ts](https://github.com/sysdevrun/dosipas-ts)
**4.1.0** (the golden files in `fixtures/` were produced by that version).

Status: complete. All test groups pass on the host (ASan+UBSan, mbedTLS 2.28
and 3.6) and on the ESP32 (`pio test -e esp32dev`, 14/14).

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

## Measurements

### Flash (ESP32, Arduino core 2.0.17, `-Os`, `xtensa-esp32-elf-size` on the library objects)

| Object | text bytes |
|---|---|
| `dosipas_schema_tables.c` (all schemas) | 20,944 |
| `dosipas_ticket.c` (flow + typed binding + time helpers) | 9,171 |
| `dosipas_decode.c` (UPER runtime + arena) | 4,686 |
| `dosipas_summary.c` | 4,143 |
| `dosipas_json.c` | 2,445 |
| **Decoding total (without verification)** | **41,389** |
| `dosipas_verify.c` (OID rules, DER/key parsing, mbedTLS glue) | 6,742 |

The example sketch firmware is 349,488 bytes with verification and 310,480
bytes without (`esp32dev_noverify` env), so signature verification costs about
39 KB of flash in total: the 6.7 KB above plus the mbedTLS bignum/ECP/ECDSA/SHA
code pulled from the core's precompiled `libmbedcrypto.a` (shared with TLS when
WiFi is used). The decoder itself is well under the 300 KB target.

For comparison, the asn1c prototype measured at `-Os` for xtensa: FCB3 types
alone 110 KB text + 59 KB data, header v2 67 KB, runtime 38 KB (PER only) to
80 KB.

### RAM (arena peak per fixture, host and ESP32 are identical: same allocations)

Recommended arena: 16 KB (`DOSIPAS_RECOMMENDED_ARENA_SIZE`), more than 2x the
largest fixture.

| Fixture | Payload | Arena peak |
|---|---|---|
| CAR_JAUNE (x6) | 154-156 B | 3072-3080 B |
| SAMPLE | 307 B | 5152 B |
| BUS_ARDECHE / BUS_AIN / DROME_BUS | 351-357 B | 5080-5176 B |
| SOLEA | 412 B | 5808 B |
| GRAND_EST_U1_FCB3 | 450 B | 5832 B |
| SNCF_TER | 212 B | 6040 B |
| CTS | 424 B | 6328 B |

Static RAM of the example firmware: 40,864 B with verification, 40,808 B
without (the 16 KB arena and the 2 KB payload buffer included).

### Time

Host (Apple M-series, release): decode 1-3 us, JSON 1-3 us, level 2 ECDSA
verify about 0.8 ms per fixture.

ESP32-D0WD-V3 at 240 MHz, Arduino core 2.0.17, `pio test -e esp32dev`
(`metrics` test; heapmin = minimum free heap during the run, stackHWM =
`uxTaskGetStackHighWaterMark` of the 8 KB Arduino loop task, i.e. bytes never
used; arena peaks are smaller than on the host because pointers are 4 bytes):

| Fixture | Payload | Arena peak | Stack never used | Decode | JSON | Level 2 verify |
|---|---|---|---|---|---|---|
| CAR_JAUNE (x6) | 154-156 B | 2360-2368 B | 3824 B | 0.35-0.92 ms | 0.37-0.58 ms | no signature |
| SAMPLE | 307 B | 4088 B | 3824 B | 1.25 ms | 0.88 ms | 216 ms (invalid) |
| SNCF_TER | 212 B | 4608 B | 3824 B | 1.43 ms | 1.00 ms | no signature |
| BUS_ARDECHE / BUS_AIN / DROME_BUS | 351-357 B | 4048-4128 B | 3824 B | 0.92-1.39 ms | 0.86-0.98 ms | 409-412 ms |
| SOLEA | 412 B | 4632 B | 3824 B | 0.82 ms | 0.80 ms | 410 ms |
| GRAND_EST_U1_FCB3 | 450 B | 4664 B | 3824 B | 1.44 ms | 1.00 ms | 404 ms |
| CTS | 424 B | 5056 B | 3824 B | 1.01 ms | 0.87 ms | 411 ms |

Minimum free heap during the whole run: 197,748 B (the test suite itself
mallocs the 16 KB arena, a 16 KB JSON buffer and the parsed goldens). The
decoder and binder allocate nothing on the heap; mbedTLS allocates its
bignums during verification and frees them. ECDSA P-256 verification takes
about 0.41 s on the ESP32 with the core's software bignum; decoding and JSON
are about a millisecond each.

The first decode of a run is slower (0.9 ms vs 0.35 ms for Car Jaune) while
the flash cache warms up.

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

## Definition of done

- Every dosipas-ts fixture decodes on the host and on the ESP32 to JSON equal
  to dosipas-ts output: yes (14/14, `golden` group on both).
- Level 2 signatures verify on the host and on the ESP32 with the same result
  as dosipas-ts: yes; level 1 too where the registry has the key.
- Truncated, bit-flipped and fuzzed inputs never crash and pass the sanitizers:
  yes (host ASan+UBSan, 10.1 million fuzz inputs, same robustness groups on the
  ESP32).
- Flash, heap, stack and timing measured and documented: above.
- The example sketch builds for `esp32dev`: yes.

License: MIT.
