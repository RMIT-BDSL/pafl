#!/bin/zsh
set -u; cd "$(dirname "$0")/.."; PY=.venv/bin/python
log() { echo "[$(date '+%H:%M:%S')] $*"; }
for FAB in splice_only channel_roll; do
  log "wadi adaptive $FAB"
  $PY -W ignore scripts/day45_adaptive.py --dataset wadi --defences fedavg trimmed_mean fltrust \
    --fabrication $FAB --roll-shift 60 --target-attack-fraction 0.10 --malicious-fraction 0.3 \
    --clients 10 --rounds 25 --local-epochs 2 --seeds 0 1 2 \
    --out results/day45_wadi_${FAB}_3seed.json 2>&1 | grep -v Warning | grep -E "day45  |gate excluded|Traceback|Error"
done
log "done-wadi"
