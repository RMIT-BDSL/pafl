#!/bin/zsh
# Overnight queue, 10->11 Sep. Sequential so runs do not contend for the CPU.
# Every driver is resumable: re-running this script skips finished cells.
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
WIDE=(--r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005)
ALL7=(fedavg krum median trimmed_mean norm_clip fltrust foolsgold)
log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "0/6 add the gated mode to the narrow-set files already run (3 rules)"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --defences fedavg trimmed_mean fltrust \
  --fabrication channel_roll --roll-shift 60 --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --seeds 0 1 2 --out results/day45_swat_roll60_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --defences fedavg trimmed_mean fltrust \
  --fabrication channel_roll --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --seeds 0 --out results/day45_swat_roll7_s0.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded"

log "1/6 SWaT adaptive, wide set, all 7 rules, channel roll @60 (extends the 3-rule file)"
$PY -W ignore scripts/day45_adaptive.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" \
  --fabrication channel_roll --roll-shift 60 --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --seeds 0 1 2 --out results/day45_swat_wide_roll60_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|CRITERION|removed"

log "2/6 SWaT adaptive, wide set, all 7 rules, splice-only (extends the 3-rule file)"
$PY -W ignore scripts/day45_adaptive.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" \
  --fabrication splice_only --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --seeds 0 1 2 --out results/day45_swat_wide_splice_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|CRITERION|removed"

log "3/6 SWaT baselines sweep, wide set: 7 rules x {splice_only, channel_roll@60, within_regime_permutation, sign_flip, scaling, free_rider, min_max} x 3 seeds"
$PY -W ignore scripts/week2_baselines.py --dataset swat "${WIDE[@]}" --defences "${ALL7[@]}" \
  --attacks splice_only channel_roll within_regime_permutation sign_flip scaling free_rider min_max \
  --roll-shift 60 --malicious-fractions 0.0 0.3 --clients 10 --rounds 25 --seeds 0 1 2 \
  --out results/week2_baselines_swat_wide.json 2>&1 | grep -v Warning | grep -E "week2  |wrote"

log "4/6 SWaT 4b: fltrust + foolsgold trust traces, wide set, channel roll @60, 3 seeds"
$PY -W ignore scripts/week2_4b.py --dataset swat "${WIDE[@]}" --defences fltrust foolsgold \
  --roll-shift 60 --malicious-fraction 0.3 --clients 10 --rounds 25 --seeds 0 1 2 \
  --out results/week2_4b_swat_wide.json 2>&1 | grep -v Warning | grep -E "week2_4b |NOTE|wrote"

log "5/6 BATADAL support: adaptive (5 clients) for channel roll and splice-only, 3 seeds, 3 rules"
$PY -W ignore scripts/day45_adaptive.py --dataset batadal --defences fedavg trimmed_mean fltrust \
  --fabrication channel_roll --malicious-fraction 0.3 --clients 5 --rounds 25 --local-epochs 2 \
  --seeds 0 1 2 --out results/day45_batadal_roll_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|CRITERION|removed"
$PY -W ignore scripts/day45_adaptive.py --dataset batadal --defences fedavg trimmed_mean fltrust \
  --fabrication splice_only --malicious-fraction 0.3 --clients 5 --rounds 25 --local-epochs 2 \
  --seeds 0 1 2 --out results/day45_batadal_splice_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|CRITERION|removed"

log "6/6 Recipe B trial: one FedAvg cell on SWaT (first-order path)"
$PY -W ignore scripts/week2_baselines.py --dataset swat "${WIDE[@]}" --defences fedavg \
  --attacks recipe_b --malicious-fractions 0.0 0.3 --clients 10 --rounds 25 --seeds 0 \
  --out results/probe_swat_recipe_b.json 2>&1 | grep -v Warning | grep -E "week2  |wrote|Error|Traceback" 

log "done"
