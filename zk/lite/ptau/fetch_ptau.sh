#!/usr/bin/env bash
# Download the powers-of-tau file PA-FL Lite's Groth16 setup uses: PSE perpetual powers of tau, 2^20,
# phase-2 prepared, 1,208,052,882 bytes (~1.2 GB). Writes ptau/ppot_0080_20.ptau next to this script, from
# any working directory. Resumes until complete, aborts a transfer that stalls below 20 KB/s for 30 s and
# retries (60 attempts), then checks the size and SHA-256. Works on macOS and Linux.
#   usage: zk/lite/ptau/fetch_ptau.sh
cd "$(dirname "$0")" || exit 1
URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_20.ptau
OUT=ppot_0080_20.ptau
WANT=1208052882
SHA256=560412532a1205145d5f21585274fb2cef61273496ddc7186aec855aab01a8cd   # the file behind the paper's numbers

size() { if [ -f "$OUT" ]; then wc -c < "$OUT" | tr -d ' '; else echo 0; fi; }
sha() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$OUT"; else sha256sum "$OUT"; fi | cut -d' ' -f1; }

for i in $(seq 1 60); do
  have=$(size)
  if [ "$have" -ge "$WANT" ]; then
    echo "complete: $have bytes; checking SHA-256 ..."
    got=$(sha)
    if [ "$got" = "$SHA256" ]; then echo "SHA-256 ok"; exit 0; fi
    echo "SHA-256 mismatch: got $got, want $SHA256 (delete $OUT and run again)"; exit 1
  fi
  echo "$(date +%T) attempt $i, have $have of $WANT bytes"
  curl -L -C - -sS --speed-limit 20000 --speed-time 30 -o "$OUT" "$URL" || sleep 5
done
echo "gave up after 60 attempts"; exit 1
