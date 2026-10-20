#!/bin/sh
# Build the libFuzzer target with ASan + UBSan and run it on the fixture corpus.
#
#   fuzz/run.sh [max_total_time_seconds]   (default 60)
#
# Uses $CLANG, else Homebrew LLVM (/opt/homebrew/opt/llvm/bin/clang), else clang.
# Apple's clang does not ship libFuzzer: `brew install llvm`.
# Findings land in fuzz/findings/ (crash-*, leak-*, timeout-*).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SECONDS_MAX="${1:-60}"
CLANG="${CLANG:-}"
if [ -z "$CLANG" ]; then
    for c in /opt/homebrew/opt/llvm/bin/clang /usr/local/opt/llvm/bin/clang clang; do
        if command -v "$c" >/dev/null 2>&1; then CLANG="$c"; break; fi
    done
fi
mkdir -p "$HERE/build" "$HERE/findings"
echo "building fuzz target with $CLANG"
"$CLANG" -std=c99 -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
    -I"$ROOT/src" -DDOSIPAS_WITH_MBEDTLS=0 \
    "$ROOT"/src/dosipas_decode.c "$ROOT"/src/dosipas_ticket.c "$ROOT"/src/dosipas_json.c \
    "$ROOT"/src/dosipas_summary.c "$ROOT"/src/dosipas_schema_tables.c "$ROOT"/src/dosipas_verify.c \
    "$HERE/fuzz_decode.c" -o "$HERE/build/fuzz_decode"
echo "running for $SECONDS_MAX s on $HERE/corpus/decode"
"$HERE/build/fuzz_decode" -max_total_time="$SECONDS_MAX" -max_len=2048 -artifact_prefix="$HERE/findings/" \
    "$HERE/corpus/decode" 2>&1 | tail -15
