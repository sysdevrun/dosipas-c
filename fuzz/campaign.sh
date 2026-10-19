#!/bin/sh
# Long fuzzing campaign on N cores (default 3) until no new branch for STALL_HOURS (default 24).
#
#   fuzz/campaign.sh            run in tmux/screen or with nohup; logs to fuzz/work/campaign.log
#
# Workers share the corpora in fuzz/work/<target>/ (seeded from fuzz/corpus*/):
#   1: libFuzzer, cycles fuzz_decode, fuzz_schema, fuzz_decode.m32, fuzz_schema.m32
#   2: libFuzzer, cycles fuzz_verify, fuzz_keys
#   3: AFL++ (cmplog-free, ASan), cycles fuzz_decode.afl, fuzz_schema.afl, fuzz_verify.afl;
#      new queue entries are copied back into the shared corpus after each slot
# Each slot lasts SLOT seconds (default 1800). Every CHECK seconds (default 7200) fuzz/coverage.sh
# runs on the shared corpora and its covered-branch count is appended to fuzz/work/coverage.tsv;
# when that count has not grown for STALL_HOURS the campaign stops. Crashes: fuzz/findings/.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$HERE/work"
B="$HERE/build"
SLOT="${SLOT:-1800}"
CHECK="${CHECK:-7200}"
STALL_HOURS="${STALL_HOURS:-24}"
LOG="$W/campaign.log"
mkdir -p "$W" "$HERE/findings"
for t in decode schema verify keys; do mkdir -p "$W/$t"; done
echo "$$" > "$W/campaign.pid"
log() { echo "$(date -u +%FT%TZ) $*" >> "$LOG"; }

libfuzzer() { # target binary, corpus
    "$B/$1" -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -use_value_profile=1 \
        -max_len=4096 -timeout=10 -rss_limit_mb=2048 -dict="$HERE/dosipas.dict" \
        -max_total_time="$SLOT" -artifact_prefix="$HERE/findings/$1-" "$W/$2" >> "$W/$1.log" 2>&1
}

worker1() { while :; do for x in fuzz_decode:decode fuzz_schema:schema fuzz_decode.m32:decode fuzz_schema.m32:schema; do
    libfuzzer "${x%%:*}" "${x##*:}"; done; done; }
worker2() { while :; do for x in fuzz_verify:verify fuzz_keys:keys; do libfuzzer "${x%%:*}" "${x##*:}"; done; done; }
worker3() {
    while :; do for t in decode schema verify; do
        out="$W/afl-$t"
        rm -rf "$out"
        AFL_SKIP_CPUFREQ=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 AFL_IMPORT_FIRST=1 AFL_FAST_CAL=1 \
            timeout -s INT "$SLOT" afl-fuzz -i "$W/$t" -o "$out" -x "$HERE/dosipas.dict" -m none -t 2000 \
            -- "$B/fuzz_$t.afl" >> "$W/afl.log" 2>&1
        cp -n "$out"/default/queue/id* "$W/$t/" 2>/dev/null
        for c in "$out"/default/crashes/id*; do [ -f "$c" ] && cp "$c" "$HERE/findings/afl-$t-$(sha1sum "$c" | cut -c1-16)"; done
    done; done
}

covered() { "$HERE/coverage.sh" "$W" 2>/dev/null | awk '/^TOTAL/ {print $11 - $12}'; }

worker1 & p1=$!
worker2 & p2=$!
worker3 & p3=$!
trap 'kill $p1 $p2 $p3 2>/dev/null; pkill -P $p1; pkill -P $p2; pkill -P $p3; log stopped; exit 0' INT TERM
log "started workers $p1 $p2 $p3 (slot ${SLOT}s, check ${CHECK}s, stall ${STALL_HOURS}h)"
best=0; best_at=$(date +%s)
while :; do
    sleep "$CHECK"
    n=$(covered); now=$(date +%s)
    findings=$(ls "$HERE/findings" | wc -l)
    printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$n" "$findings" >> "$W/coverage.tsv"
    if [ -n "$n" ] && [ "$n" -gt "$best" ]; then best=$n; best_at=$now; fi
    log "covered branches $n (best $best), findings $findings"
    if [ $((now - best_at)) -ge $((STALL_HOURS * 3600)) ]; then
        log "no new branch for ${STALL_HOURS}h, stopping"
        kill -TERM $$
    fi
done
