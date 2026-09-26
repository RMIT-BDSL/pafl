#!/usr/bin/env bash
# End-to-end benchmark for one circuit build.
#
#   scripts/run_bench.sh <tag> <ptau> <batches.json> [vmax] [umax] [nonce]
#
# Generates main.circom for <tag> if absent (tag = <setting>_k<k>), compiles, runs the
# Groth16 setup, then for each of the four batches builds the input, generates the
# witness (a batch over budget fails here, by design), proves and verifies. Every step
# is timed with /usr/bin/time (wall seconds, peak RSS) into build/<tag>/steps.jsonl;
# scripts/collect_results.py folds those into results.json.
#
# Paths may be given from any working directory. Needs circom 2.1.9 and snarkjs 0.7.4 on
# PATH (the versions behind the paper's numbers; npm install provides neither, and the
# script stops on any other version unless PAFL_ANY_TOOLCHAIN=1), node_modules from npm
# ci, and python3. Runs on macOS (BSD time -l, stat -f) and Linux (GNU time, which must be
# installed at /usr/bin/time, e.g. the Debian/Ubuntu `time` package; stat -c). The paper's
# timings were measured on macOS. The nonce stands in for the
# verifier's round challenge; the same nonce is used for all four batches and is
# recorded per batch in results.json.
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
# lifts node's heap limit for snarkjs; 28 GB is a ceiling, not a requirement
# (setup peaks at ~3.1 GB, prove at ~3.6 GB)
export NODE_OPTIONS="--max-old-space-size=28672"

# The toolchain behind the paper's numbers. Another circom can compile to a different
# constraint count, and another snarkjs can change the timings, so stop unless told otherwise.
WANT_CIRCOM=2.1.9; WANT_SNARKJS=0.7.4
HAVE_CIRCOM=$(circom --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
HAVE_SNARKJS=$(snarkjs --version 2>&1 | grep -oE 'snarkjs@[0-9]+\.[0-9]+\.[0-9]+' | head -1)   # exits 99; the output is enough
HAVE_SNARKJS=${HAVE_SNARKJS#snarkjs@}
if [ "$HAVE_CIRCOM" != "$WANT_CIRCOM" ] || [ "$HAVE_SNARKJS" != "$WANT_SNARKJS" ]; then
  echo "toolchain: circom ${HAVE_CIRCOM:-not found} (want $WANT_CIRCOM), snarkjs ${HAVE_SNARKJS:-not found} (want $WANT_SNARKJS)" >&2
  if [ -z "${PAFL_ANY_TOOLCHAIN:-}" ]; then
    echo "install those versions (see README.md), or set PAFL_ANY_TOOLCHAIN=1 to run anyway" >&2
    exit 1
  fi
fi

# BSD (macOS) and GNU (Linux) time and stat differ in flags and in the RSS unit
if [ "$(uname)" = Darwin ]; then
  fsize() { stat -f %z "$1"; }
else
  fsize() { stat -c %s "$1"; }
fi

mkdir -p "$B"
STEPS=$B/steps.jsonl
: > "$STEPS"

# run a command under /usr/bin/time; append {step, seconds, max_rss_bytes, exit} to STEPS.
# seconds is wall time of the whole process (node start-up included); max RSS is in bytes
timed() {
  local step=$1; shift
  local tf; tf=$(mktemp)
  local secs rss rc
  if [ "$(uname)" = Darwin ]; then
    /usr/bin/time -l "$@" 2> "$tf"
    rc=$?
    secs=$(awk '/ real /{print $1}' "$tf" | tail -1)
    rss=$(awk '/maximum resident set size/{print $1}' "$tf" | tail -1)       # bytes
  else
    /usr/bin/time -f "PAFL_TIME %e %M" "$@" 2> "$tf"
    rc=$?
    secs=$(awk '/^PAFL_TIME /{print $2}' "$tf" | tail -1)
    rss=$(awk '/^PAFL_TIME /{print $3 * 1024}' "$tf" | tail -1)               # GNU %M is KiB
  fi
  # anything the command wrote to stderr other than the time report
  grep -vE ' real | user | sys$|maximum resident|average |page |swaps|block |messages |signals |voluntary |involuntary |instructions retired|cycles elapsed|peak memory|^PAFL_TIME ' "$tf" | grep -v '^\s*$' | tail -5 >&2
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

# No phase-2 contribution: the key is deterministic given the r1cs and ptau, which makes the
# setup reproducible and also forgeable, so it serves for timing only
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
  [ -f "$f" ] && printf '    %-22s %12d bytes\n' "$f" "$(fsize "$f")"
done
python3 "$LITE/scripts/collect_results.py" "$TAG" && echo "== $TAG: done =="
