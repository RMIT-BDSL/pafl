#!/bin/zsh
# The narrow invariant set (miner defaults: r2 0.60 / off-ratio 0.05 / support 0.02, 5 SWaT rules)
# for both headline attackers, like-for-like with the wide-set files: 7 rules, 5 modes, seeds 0-4.
# Supersedes results/swat_adaptive_narrow_roll60_3seed.json (3 rules, 3 seeds, no honest_only/gated).
set -u
cd "$(dirname "$0")/.."
PY=.venv/bin/python
ALL7=(fedavg krum median trimmed_mean norm_clip fltrust foolsgold)
log() { echo "[$(date '+%H:%M:%S')] $*"; }
log "1/2 SWaT narrow, splice-only (replay), 7 rules, 5 modes, seeds 0-4"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --defences "${ALL7[@]}" --fabrication splice_only \
  --malicious-fraction 0.3 --clients 10 --rounds 25 --local-epochs 2 \
  --modes clean honest_only fabricated projected gated --seeds 0 1 2 3 4 \
  --out results/swat_adaptive_narrow_splice_5seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|Traceback|Error"
log "2/2 SWaT narrow, channel roll @60, 7 rules, 5 modes, seeds 0-4"
$PY -W ignore scripts/day45_adaptive.py --dataset swat --defences "${ALL7[@]}" --fabrication channel_roll --roll-shift 60 \
  --malicious-fraction 0.3 --clients 10 --rounds 25 --local-epochs 2 \
  --modes clean honest_only fabricated projected gated --seeds 0 1 2 3 4 \
  --out results/swat_adaptive_narrow_roll60_5seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|Traceback|Error"
log "done-narrow"
