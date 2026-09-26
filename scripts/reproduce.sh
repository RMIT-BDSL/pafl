#!/usr/bin/env bash
# Rerun every experiment behind the committed result files in results/, one command per file.
#
#   scripts/reproduce.sh [group ...]         groups below; no argument runs them all, in this order
#   DRY=1 scripts/reproduce.sh adaptive      print the commands without running them
#   OUT=results scripts/reproduce.sh ...     write over the committed files instead (see below)
#
#   separation   criterion 1: honest vs fabricated batch separation   c1_*.json            minutes, no training
#   coverage     which labelled attacks each invariant set sees       *_coverage.json      minutes, no training
#   honest       the check's verdict on every honest shard            honest_verdicts.json minutes, no training
#   adaptive     five federated modes x aggregation rules              *_adaptive_*.json    ~4.5 h
#   sweep        every rule against every data and update attack      swat_sweep_*.json    ~1 h
#   trust        FLTrust / FoolsGold trust per round                  swat_trust_traces_*  ~5 min
#
# Times are single-process CPU wall-clock on an Apple M3 Pro, summed from the cells' wall_seconds.
# Every group needs the datasets in data/ (DATA.md).
#
# Output goes to results_archive/reproduce/ by default, so the committed files stay untouched. Compare
# each rerun with its committed version:
#     python scripts/compare_results.py results/<name>.json results_archive/reproduce/<name>.json
# The drivers resume: a rerun with the same --out skips cells already present, so delete a partial
# rerun file to start that file over. With OUT=results an already-complete file is left as it is,
# except that its summary block is recomputed.
#
# Invariant settings: "narrow" = the miner defaults (r2 0.60, coupling off-ratio 0.05, support 0.02);
# "wide" = r2 0.40, off-ratio 0.10, support 0.005. WADI's "default" is the narrow thresholds.
# Paper settings throughout: 10 clients (BATADAL 5), 3 malicious (malicious fraction 0.3), 25 rounds,
# 2 local epochs, window 10, alarm threshold at the 0.995 quantile of clean validation scores.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${PY:-}" ]; then
  if [ -x .venv/bin/python ]; then PY=.venv/bin/python; else PY=python3; fi
fi
OUT=${OUT:-results_archive/reproduce}
mkdir -p "$OUT"

WIDE=(--r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005)
ALL7=(fedavg krum median trimmed_mean norm_clip fltrust foolsgold)
THREE=(fedavg trimmed_mean fltrust)          # the rule subset of the smaller supporting runs
FED=(--malicious-fraction 0.3 --rounds 25 --local-epochs 2)

run() {
  echo "+ $*"
  if [ -z "${DRY:-}" ]; then "$PY" -W ignore "$@"; fi
}

separation() {
  # SWaT narrow and wide, WADI default; channel roll by 60 rows (5 min at the 5 s stride)
  run scripts/separation.py --dataset swat --roll-shift 60  --out "$OUT/c1_swat_narrow_shift60.json"
  run scripts/separation.py --dataset swat --roll-shift 60 "${WIDE[@]}" --out "$OUT/c1_swat_wide_shift60.json"
  run scripts/separation.py --dataset wadi --roll-shift 60  --out "$OUT/c1_wadi_default_shift60.json"
  # BATADAL: the fitted set, then the generic miner; HAI: always the generic miner (the scope boundary)
  run scripts/separation.py --dataset batadal         --out "$OUT/c1_batadal_expert.json"
  run scripts/separation.py --dataset batadal --mined --out "$OUT/c1_batadal_mined.json"
  run scripts/separation.py --dataset hai --hai-train-files 3 --hai-rows 46000 \
    --out "$OUT/c1_hai_mined.json"            # the pilot's row budget; the default (30,000) mines a different set
}

coverage() {
  run scripts/coverage.py --dataset swat --settings narrow wide --out "$OUT/swat_coverage.json"
  run scripts/coverage.py --dataset wadi --settings default     --out "$OUT/wadi_coverage.json"
}

honest() {
  run scripts/honest_verdicts.py --out "$OUT/honest_verdicts.json"
}

adaptive() {
  # SWaT, the headline files: both invariant sets x both attackers, 7 rules, all 5 modes, seeds 0-4
  run scripts/adaptive.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" --fabrication splice_only \
    "${FED[@]}" --clients 10 --seeds 0 1 2 3 4 --out "$OUT/swat_adaptive_wide_splice_5seed.json"
  run scripts/adaptive.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" --fabrication channel_roll --roll-shift 60 \
    "${FED[@]}" --clients 10 --seeds 0 1 2 3 4 --out "$OUT/swat_adaptive_wide_roll60_5seed.json"
  run scripts/adaptive.py --dataset swat --defences "${ALL7[@]}" --fabrication splice_only \
    "${FED[@]}" --clients 10 --seeds 0 1 2 3 4 --out "$OUT/swat_adaptive_narrow_splice_5seed.json"
  run scripts/adaptive.py --dataset swat --defences "${ALL7[@]}" --fabrication channel_roll --roll-shift 60 \
    "${FED[@]}" --clients 10 --seeds 0 1 2 3 4 --out "$OUT/swat_adaptive_narrow_roll60_5seed.json"
  # WADI: three rules, 3 seeds; a 10 % target budget, so that some attacks stay untargeted
  run scripts/adaptive.py --dataset wadi --defences "${THREE[@]}" --fabrication splice_only --roll-shift 60 \
    --target-attack-fraction 0.10 "${FED[@]}" --clients 10 --seeds 0 1 2 \
    --out "$OUT/wadi_adaptive_default_splice_3seed.json"
  run scripts/adaptive.py --dataset wadi --defences "${THREE[@]}" --fabrication channel_roll --roll-shift 60 \
    --target-attack-fraction 0.10 "${FED[@]}" --clients 10 --seeds 0 1 2 \
    --out "$OUT/wadi_adaptive_default_roll60_3seed.json"
  # BATADAL: 5 clients, three rules, four modes, 3 seeds, the recipe's 7-row roll
  run scripts/adaptive.py --dataset batadal --defences "${THREE[@]}" --fabrication splice_only \
    --modes clean fabricated projected gated "${FED[@]}" --clients 5 --seeds 0 1 2 \
    --out "$OUT/batadal_adaptive_splice_3seed.json"
  run scripts/adaptive.py --dataset batadal --defences "${THREE[@]}" --fabrication channel_roll \
    --modes clean fabricated projected gated "${FED[@]}" --clients 5 --seeds 0 1 2 \
    --out "$OUT/batadal_adaptive_roll_3seed.json"
}

sweep() {
  # SWaT, wide set: 7 rules x 4 data-space attacks + 4 update-space attacks, 3 seeds
  run scripts/sweep.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" \
    --attacks splice_only channel_roll within_regime_permutation sign_flip scaling free_rider min_max recipe_b \
    --roll-shift 60 --malicious-fractions 0.0 0.3 --clients 10 --rounds 25 --local-epochs 2 --seeds 0 1 2 \
    --out "$OUT/swat_sweep_wide_3seed.json"
}

trust() {
  # channel roll only (trust_traces.py has no --fabrication flag)
  run scripts/trust_traces.py --dataset swat "${WIDE[@]}" --defences fltrust foolsgold --roll-shift 60 \
    --malicious-fraction 0.3 --clients 10 --rounds 25 --local-epochs 2 --seeds 0 1 2 \
    --out "$OUT/swat_trust_traces_wide_3seed.json"
}

ALL_GROUPS=(separation coverage honest adaptive sweep trust)
if [ $# -eq 0 ]; then set -- "${ALL_GROUPS[@]}"; fi
for g in "$@"; do
  case " ${ALL_GROUPS[*]} " in
    *" $g "*) echo "== $g"; "$g" ;;
    *) echo "unknown group '$g'; choose from: ${ALL_GROUPS[*]}" >&2; exit 2 ;;
  esac
done
