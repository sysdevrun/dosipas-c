#!/bin/sh
# Branch/line coverage of src/ reached by the fuzz corpora, with the .cov builds of fuzz/build.sh.
#
#   fuzz/coverage.sh [corpus root]   (default fuzz/work: one sub-directory per target,
#                                     decode/ schema/ verify/ keys/)
#
# Prints the llvm-cov summary per file; HTML report in fuzz/build/coverage/index.html.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CORPUS="${1:-$HERE/work}"
PROFDATA="$(command -v llvm-profdata-16 || command -v llvm-profdata)"
COV="$(command -v llvm-cov-16 || command -v llvm-cov)"
OUT="$HERE/build/profiles"
rm -rf "$OUT"
mkdir -p "$OUT"
objs=""
for t in decode schema verify keys; do
    [ -d "$CORPUS/$t" ] || continue
    LLVM_PROFILE_FILE="$OUT/$t.profraw" "$HERE/build/fuzz_$t.cov" "$CORPUS/$t" >/dev/null 2>&1 || true
    objs="$objs -object $HERE/build/fuzz_$t.cov"
done
"$PROFDATA" merge -sparse "$OUT"/*.profraw -o "$OUT/all.profdata"
first="$(echo "$objs" | awk '{print $2}')"
rest="$(echo "$objs" | cut -d' ' -f4-)"
# shellcheck disable=SC2086
"$COV" report "$first" $rest -instr-profile="$OUT/all.profdata" -show-branch-summary "$ROOT"/src/*.c
# shellcheck disable=SC2086
"$COV" show "$first" $rest -instr-profile="$OUT/all.profdata" -show-branches=count -format=html \
    -output-dir="$HERE/build/coverage" "$ROOT"/src/*.c >/dev/null
