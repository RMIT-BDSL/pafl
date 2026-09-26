#!/usr/bin/env bash
# Many rounds of the protocol on one compiled build, witness generation only (no proofs):
# for each nonce, derive the k indices, build the input, and see whether a witness exists.
# A witness exists iff the sampled rows are within the budgets, so this measures the honest
# false-reject rate and the detection rate on the real circuit, one nonce = one round.
#
#   scripts/nonce_sweep.sh <tag> <batches.json> [rounds] [vmax] [umax]
#   scripts/nonce_sweep.sh wide_k32 data/batches_swat_wide_seed0.json 40 1 8
#
# Needs build/<tag>/main_js from run_bench.sh, node, python3 and bc. Nonces are 1..rounds,
# so a rerun repeats the same rounds. Per-round lines go to build/<tag>/nonce_sweep_v<v>_u<u>.jsonl,
# which is not committed; the 40-round table in README.md is its printed summary.
set -uo pipefail
LITE=$(cd "$(dirname "$0")/.." && pwd)
TAG=$1; BATCHES=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); ROUNDS=${3:-40}; VMAX=${4:-1}; UMAX=${5:-8}
B=$LITE/build/$TAG
OUT=$B/nonce_sweep_v${VMAX}_u${UMAX}.jsonl
: > "$OUT"
SCR=$(mktemp -d)
for batch in honest projected channel_roll splice_only; do
  pass=0; fail=0; vsum=0; usum=0
  for nonce in $(seq 1 "$ROUNDS"); do
    node "$LITE/scripts/build_inputs.mjs" --meta "$B/circuit_meta.json" --batches "$BATCHES" --batch "$batch" \
         --nonce "$nonce" --vmax "$VMAX" --umax "$UMAX" --out "$SCR/in.json" > /dev/null 2>&1 || { echo "input build failed"; exit 1; }
    v=$(python3 -c "import json;print(json.load(open('$SCR/in.expect.json'))['violations'])")
    u=$(python3 -c "import json;print(json.load(open('$SCR/in.expect.json'))['inapplicable'])")
    if node "$B/main_js/generate_witness.js" "$B/main_js/main.wasm" "$SCR/in.json" "$SCR/w.wtns" > /dev/null 2>&1; then ok=1; pass=$((pass+1)); else ok=0; fail=$((fail+1)); fi
    vsum=$((vsum+v)); usum=$((usum+u))
    printf '{"batch":"%s","nonce":%d,"v":%d,"u":%d,"witness":%d}\n' "$batch" "$nonce" "$v" "$u" "$ok" >> "$OUT"
  done
  printf '%-13s rounds %d: witness exists %d, aborts %d  (mean v %.2f, mean u %.2f)\n' "$batch" "$ROUNDS" "$pass" "$fail" \
         "$(echo "$vsum / $ROUNDS" | bc -l)" "$(echo "$usum / $ROUNDS" | bc -l)"
done
rm -rf "$SCR"
echo "wrote $OUT"
