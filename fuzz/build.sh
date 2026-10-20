#!/bin/sh
# Build every fuzz target (Linux, clang with libFuzzer) into fuzz/build/:
#   <target>        libFuzzer + ASan + UBSan
#   <target>.cov    plain binary with clang source coverage (for fuzz/coverage.sh)
#   <target>.afl    AFL++ (afl-clang-fast) + ASan, when afl-clang-fast is installed
#   <target>.m32    libFuzzer + ASan + UBSan for i386 (4-byte pointers like the ESP32),
#                   decode/schema only, when the i386 libFuzzer runtime is installed
#
#   fuzz/build.sh          (CLANG=clang-16 by default when installed, else clang)
#
# fuzz_verify and fuzz_keys need mbedTLS: built once into .deps/ by tools/fetch_mbedtls.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CLANG="${CLANG:-$(command -v clang-16 || command -v clang)}"
TAG="${MBEDTLS_TAG:-v3.6.4}"
MBED="$ROOT/.deps/mbedtls-$TAG"
sh "$ROOT/tools/fetch_mbedtls.sh" "$TAG" "$MBED" >/dev/null
OUT="$HERE/build"
mkdir -p "$OUT"
LIB="$ROOT/src/dosipas_decode.c $ROOT/src/dosipas_ticket.c $ROOT/src/dosipas_json.c $ROOT/src/dosipas_summary.c \
     $ROOT/src/dosipas_schema_tables.c $ROOT/src/dosipas_verify.c"
INC="-std=c99 -g -I$ROOT/src -I$MBED/include -DDOSIPAS_WITH_MBEDTLS=1"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
LINK="$MBED/lib/libmbedcrypto.a"
for t in decode schema verify keys; do
    echo "fuzz_$t"
    # shellcheck disable=SC2086
    "$CLANG" $INC -O1 -fsanitize=fuzzer $SAN $LIB "$HERE/fuzz_$t.c" $LINK -o "$OUT/fuzz_$t"
    # shellcheck disable=SC2086
    "$CLANG" $INC -O0 -fprofile-instr-generate -fcoverage-mapping $LIB "$HERE/fuzz_$t.c" \
        "$HERE/standalone_main.c" $LINK -o "$OUT/fuzz_$t.cov"
    if command -v afl-clang-fast >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        AFL_QUIET=1 AFL_USE_ASAN=1 afl-clang-fast $INC -O1 -fsanitize=fuzzer $LIB "$HERE/fuzz_$t.c" $LINK \
            -o "$OUT/fuzz_$t.afl"
    fi
done
for t in decode schema; do
    # shellcheck disable=SC2086
    "$CLANG" -m32 -std=c99 -g -I"$ROOT/src" -DDOSIPAS_WITH_MBEDTLS=0 -O1 -fsanitize=fuzzer $SAN $LIB \
        "$HERE/fuzz_$t.c" -o "$OUT/fuzz_$t.m32" 2>/dev/null && echo "fuzz_$t.m32" || echo "no i386 toolchain, skipping fuzz_$t.m32"
done
