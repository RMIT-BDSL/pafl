#!/usr/bin/env bash
# End-to-end benchmark for one circuit build.
#
#   scripts/run_bench.sh <tag> <ptau> <batches.json> [vmax] [umax] [nonce]
#
# Generates main.circom for <tag> if absent (tag = <setting>_k<k>), compiles, runs the
# Groth16 setup, then for each of the four batches builds the input, generates the
# witness (a batch over budget fails here, by design), proves and verifies. Every step
# is timed with /usr/bin/time -l (wall seconds, peak RSS) into build/<tag>/steps.jsonl;
# scripts/collect_results.py folds those into results.json.
set -uo pipefail

LITE=$(cd "$(dirname "$0")/.." && pwd)
TAG=${1:?tag, e.g. wide_k32}
PTAU=$(cd "$(dirname "${2:?ptau file}")" && pwd)/$(basename "$2")
BATCHES=$(cd "$(dirname "${3:?batches json}")" && pwd)/$(basename "$3")
VMAX=${4:-1}
UMAX=${5:-8}
NONCE=${6:-1}
B=$LITE/build/$TAG
LIB=$LITE/node_modules
export NODE_OPTIONS="--max-old-space-size=28672"
mkdir -p "$B"
STEPS=$B/steps.jsonl
: > "$STEPS"

# run a command under /usr/bin/time -l; append {step, seconds, max_rss_bytes, exit} to STEPS
timed() {
  local step=$1; shift
  local tf; tf=$(mktemp)
  /usr/bin/time -l "$@" 2> "$tf"
  local rc=$?
  local secs rss
  secs=$(awk '/ real /{print $1}' "$tf" | tail -1)
  rss=$(awk '/maximum resident set size/{print $1}' "$tf" | tail -1)
  # anything the command wrote to stderr other than the time report
  grep -vE ' real | user | sys$|maximum resident|average |page |swaps|block |messages |signals |voluntary |involuntary |instructions retired|cycles elapsed|peak memory' "$tf" | grep -v '^\s*$' | tail -5 >&2
  rm -f "$tf"
  printf '{"step":"%s","seconds":%s,"max_rss_bytes":%s,"exit":%d}\n' "$step" "${secs:-null}" "${rss:-null}" "$rc" >> "$STEPS"
  printf '    -> %s: %ss, %s MB peak, exit %d\n' "$step" "${secs:-?}" "$(( ${rss:-0} / 1048576 ))" "$rc"
  return $rc
}

echo "== $TAG: compile =="
if [ ! -f "$B/main.circom" ]; then
  K=${TAG##*_k}; SETTING=${TAG%_k*}
  python3 "$LITE/scripts/gen_main.py" --k "$K" --tag "$TAG" \
    --invariants "$LITE/../data/invariants_swat_${SETTING}.json" || exit 1
fi
cd "$B"
timed compile circom main.circom --r1cs --wasm --sym -l "$LIB" -o . > compile.log || { cat compile.log; exit 1; }
grep -E "non-linear constraints|linear constraints|wires|public inputs|private inputs" compile.log
snarkjs r1cs info main.r1cs > r1cs_info.txt 2>&1
grep -E "Constraints|Wires|Public|Private" r1cs_info.txt | sed 's/.*snarkJS: //'

echo "== $TAG: groth16 setup (no phase-2 contribution: benchmark setup only) =="
timed setup snarkjs groth16 setup main.r1cs "$PTAU" circuit.zkey > setup.log || { tail -5 setup.log; exit 1; }
timed export_vk snarkjs zkey export verificationkey circuit.zkey vk.json > /dev/null

for batch in honest channel_roll projected splice_only; do
  echo "== $TAG: $batch (vMax=$VMAX uMax=$UMAX nonce=$NONCE) =="
  node "$LITE/scripts/build_inputs.mjs" --meta circuit_meta.json --batches "$BATCHES" --batch "$batch" \
       --nonce "$NONCE" --vmax "$VMAX" --umax "$UMAX" --out "input_$batch.json" || exit 1
  if timed "witness_$batch" node main_js/generate_witness.js main_js/main.wasm "input_$batch.json" "witness_$batch.wtns" 2> "witness_$batch.err"; then
    timed "prove_$batch" snarkjs groth16 prove circuit.zkey "witness_$batch.wtns" "proof_$batch.json" "public_$batch.json" > /dev/null
    timed "verify_$batch" snarkjs groth16 verify vk.json "public_$batch.json" "proof_$batch.json" > "verify_$batch.log"
    grep -q "OK!" "verify_$batch.log" && echo "    verify: OK" || { echo "    verify: FAILED"; cat "verify_$batch.log"; }
  else
    echo "    witness generation failed (constraint not satisfied): $(grep -oE 'Error in template [^ ]+ line: [0-9]+' "witness_$batch.err" | head -1)"
  fi
done

echo "== $TAG: sizes =="
echo "    ptau: $PTAU"
echo "{\"step\":\"ptau\",\"path\":\"$PTAU\"}" >> "$STEPS"
for f in main.r1cs main_js/main.wasm circuit.zkey vk.json proof_honest.json input_honest.json; do
  [ -f "$f" ] && printf '    %-22s %12d bytes\n' "$f" "$(stat -f %z "$f")"
done
python3 "$LITE/scripts/collect_results.py" "$TAG" && echo "== $TAG: done =="
