#!/bin/zsh
# Follow-up queue: seeds 3 and 4 for the key SWaT adaptive files (resumable; adds cells).
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
ALL7=(fedavg krum median trimmed_mean norm_clip fltrust foolsgold)
log() { echo "[$(date '+%H:%M:%S')] $*"; }
log "b1/2 SWaT wide, channel roll @60, seeds 3 4"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005 \
  --defences "${ALL7[@]}" --fabrication channel_roll --roll-shift 60 --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --modes clean honest_only fabricated projected gated --seeds 0 1 2 3 4 --out results/day45_swat_wide_roll60_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded"
log "b2/2 SWaT wide, splice-only, seeds 3 4"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --r2-min 0.40 --coupling-off-ratio 0.10 --coupling-support 0.005 \
  --defences "${ALL7[@]}" --fabrication splice_only --malicious-fraction 0.3 --clients 10 --rounds 25 \
  --local-epochs 2 --modes clean honest_only fabricated projected gated --seeds 0 1 2 3 4 --out results/day45_swat_wide_splice_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded"
log "done-b"
