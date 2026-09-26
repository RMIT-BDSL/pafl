#!/usr/bin/env python3
"""Step 2 of the ZK plan: real SWaT batches, quantised for the circuit.

Rebuilds the wide-set federation exactly as the experiments do (build_variant,
seed s, 10 clients, 3 malicious, channel roll of 60 rows) and cuts four
N-row batches out of it:

    honest        an honest client's own shard
    channel_roll  the first malicious client's fabricated shard (Recipe A)
    projected     the same shard after the adaptive attacker projects it onto the physics
    splice_only   the same client under the exposure-only attacker (real attack rows spliced in)

Rows are quantised as x_hat = round(S x) and written with the float and integer
verdicts, per-row violation / inapplicability counts, and (telemetry-free) per-row
counts over every honest shard for sizing the v / u budgets.  The file holds SWaT
rows and stays local.

The splice_only batch is the N-row window of the malicious shard with the most
spliced attack rows (for seed 0, a window made entirely of attack rows), so the
detection figures on it are for the densest window, not a typical one.

Needs the SWaT archive where pafl's loader finds it (see DATA.md at the repo root)
and the repo's virtualenv. From zk/lite:

    ../../.venv/bin/python scripts/export_batches.py --seed 0
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import sys
import time
from pathlib import Path

import numpy as np

LITE = Path(__file__).resolve().parents[1]
PAFL = LITE.parents[1]                                                     # the repo root
sys.path.insert(0, str(PAFL))

from pafl.fl.variants import build_variant                                    # noqa: E402
from pafl.zk.fixed_point import (integer_applicable, integer_verdict,          # noqa: E402
                                 integer_violations, quantise_rows)

# miner thresholds of the two invariant sets, as in zk/scripts/export_invariants.py; the
# asserts in main() stop the run if the rebuilt set differs from the export
SETTINGS = {
    "narrow": dict(r2_min=0.60, coupling_off_ratio=0.05, coupling_support=0.02),
    "wide": dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005),
}


def row_stats(X_hat: np.ndarray, q: dict) -> tuple[np.ndarray, np.ndarray]:
    """Per-row counts of violated rules and of rules that did not apply.

    Row 0 has no predecessor, so every rule counts as inapplicable there; callers
    drop it (the protocol never samples it)."""
    V = integer_violations(X_hat, q)
    A = integer_applicable(X_hat, q)
    return V.sum(axis=1).astype(int), (~A).sum(axis=1).astype(int)


def describe(df, X_hat, inv_set, q, cols, **extra) -> dict:
    v, u = row_stats(X_hat, q)
    fv = inv_set.batch_verdict(df)
    iv = integer_verdict(X_hat, q)
    return {
        "rows": X_hat.tolist(),
        "float_verdict": {"violating_fraction": fv["violating_fraction"], "admitted": fv["admitted"],
                          "per_invariant_violating_fraction": fv["per_invariant_violating_fraction"],
                          "not_applicable_fraction": fv["not_applicable_fraction"]},
        "integer_verdict": {"violating_fraction": iv["violating_fraction"], "admitted": iv["admitted"],
                            "per_invariant_violating_fraction": iv["per_invariant_violating_fraction"]},
        "row_violations": v[1:].tolist(),          # index t-1 <-> row t, t = 1..N-1
        "row_inapplicable": u[1:].tolist(),
        "violating_row_fraction": float((v[1:] > 0).mean()),
        **extra,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--setting", default="wide", choices=sorted(SETTINGS))
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--rows", type=int, default=1024)
    ap.add_argument("--roll-shift", type=int, default=60)
    ap.add_argument("--n-clients", type=int, default=10)
    ap.add_argument("--malicious-fraction", type=float, default=0.3)
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--invariants", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    inv_path = Path(a.invariants) if a.invariants else PAFL / "zk" / "data" / f"invariants_swat_{a.setting}.json"
    q = json.load(open(inv_path))
    S, cols = q["S"], q["columns"]
    N = a.rows
    out = Path(a.out) if a.out else LITE / "data" / f"batches_swat_{a.setting}_seed{a.seed}.json"

    common = dict(dataset="swat", malicious_fraction=a.malicious_fraction, n_clients=a.n_clients,
                  window=a.window, seed=a.seed, roll_shift=a.roll_shift, invariant_kw=SETTINGS[a.setting])
    t0 = time.time()
    log = lambda m: print(f"[{time.time() - t0:6.1f}s] {m}", flush=True)

    log("building the clean federation")
    clean_sc, inv_set, sc_cols = build_variant(mode="clean", fabrication="channel_roll", **common)
    assert list(sc_cols) == list(cols), "column order differs from the invariant export"
    assert inv_set.names == [i["name"] for i in q["invariants"]], "invariant set differs from the export"
    for inv, e in zip(inv_set, q["invariants"]):
        assert abs(inv.eps - e["eps"]) <= 1e-9 * max(1.0, abs(e["eps"])), f"{inv.name}: eps differs from the export"
    log(f"invariant set matches the export ({len(inv_set)} rules)")

    log("building the fabricated federation (channel roll)")
    fab_sc, _, _ = build_variant(mode="fabricated", fabrication="channel_roll", **common)
    log("building the projected federation (adaptive attacker)")
    proj_sc, _, _ = build_variant(mode="projected", fabrication="channel_roll", **common)
    log("building the exposure-only federation (splice_only)")
    spl_sc, _, _ = build_variant(mode="fabricated", fabrication="splice_only", **common)

    by_id = lambda sc: {c.client_id: c for c in sc["clients"]}
    fab, proj, spl, clean = by_id(fab_sc), by_id(proj_sc), by_id(spl_sc), by_id(clean_sc)
    mal_ids = sorted(c.client_id for c in fab_sc["clients"] if c.is_malicious)
    hon_ids = sorted(c.client_id for c in fab_sc["clients"] if not c.is_malicious)
    mid, hid = mal_ids[0], hon_ids[0]
    log(f"malicious clients {mal_ids}; batches taken from malicious client {mid} and honest client {hid}")

    value_range: dict = {}

    def quant(df):
        # the circuit biases every value by 2^31 and range-checks 32 bits, so |x_hat| < 2^31
        X = quantise_rows(df, cols, S)
        assert (X >= -2 ** 31).all() and (X < 2 ** 31).all(), "quantised value outside [-2^31, 2^31)"
        for j, c in enumerate(cols):
            lo, hi = value_range.get(c, (0, 0))
            value_range[c] = (min(lo, int(X[:, j].min())), max(hi, int(X[:, j].max())))
        return X

    batches = {}
    # honest: the first N rows of an honest shard
    df = fab[hid].raw.iloc[:N].reset_index(drop=True)
    batches["honest"] = describe(df, quant(df), inv_set, q, cols, client=hid, start=0)
    # channel roll and its projection: the same N rows of the malicious shard
    df = fab[mid].raw.iloc[:N].reset_index(drop=True)
    batches["channel_roll"] = describe(df, quant(df), inv_set, q, cols, client=mid, start=0,
                                       fabrication="channel_roll", roll_shift=a.roll_shift)
    df = proj[mid].raw.iloc[:N].reset_index(drop=True)
    pstat = next((s for s in proj_sc.get("projection", []) if s["client"] == mid), None)
    batches["projected"] = describe(df, quant(df), inv_set, q, cols, client=mid, start=0,
                                    fabrication="channel_roll+projection", projection_stats_whole_shard=pstat)
    # splice-only: the N-row window of the malicious shard holding the most spliced attack rows
    honest_shard = clean[mid].raw[cols].to_numpy(float)
    spliced_shard = spl[mid].raw[cols].to_numpy(float)
    changed = (np.abs(honest_shard - spliced_shard) > 0).any(axis=1).astype(int)
    csum = np.concatenate([[0], np.cumsum(changed)])
    win = csum[N:] - csum[:-N]
    start = int(np.argmax(win))
    df = spl[mid].raw.iloc[start:start + N].reset_index(drop=True)
    batches["splice_only"] = describe(df, quant(df), inv_set, q, cols, client=mid, start=start,
                                      fabrication="splice_only", attack_rows_in_window=int(win[start]),
                                      attack_rows_in_shard=int(changed.sum()), shard_rows=int(len(changed)))
    for name, b in batches.items():
        log(f"{name:13s} client {b['client']} rows {b['start']}..{b['start'] + N - 1}: "
            f"violating rows {b['violating_row_fraction']:.4f} (float {b['float_verdict']['violating_fraction']:.4f}), "
            f"admitted float {b['float_verdict']['admitted']} integer {b['integer_verdict']['admitted']}")

    # telemetry-free per-row counts over every honest shard, for sizing v_max / u_max
    hv, hu, spans = [], [], []
    for cid in hon_ids:
        X = quant(fab[cid].raw)
        v, u = row_stats(X, q)
        hv.append(v[1:]); hu.append(u[1:]); spans.append(len(v) - 1)
    hv, hu = np.concatenate(hv), np.concatenate(hu)
    honest_pool = {"clients": hon_ids, "rows_per_client": spans, "n_rows": int(len(hv)),
                   "violations": hv.tolist(), "inapplicable": hu.tolist(),
                   "violating_row_fraction": float((hv > 0).mean()),
                   "inapplicable_cell_rate": float(hu.mean() / len(inv_set))}
    log(f"honest pool: {len(hv)} rows over {len(hon_ids)} clients; violating rows {honest_pool['violating_row_fraction']:.4f}; "
        f"mean inapplicable rules per row {hu.mean():.4f}")

    doc = {
        "dataset": "swat", "setting": a.setting, "seed": a.seed, "N": N, "S": S, "columns": cols,
        "invariants_file": str(inv_path), "invariant_names": inv_set.names,
        "construction": {"n_clients": a.n_clients, "malicious_fraction": a.malicious_fraction,
                         "roll_shift": a.roll_shift, "window": a.window, "malicious_clients": mal_ids,
                         "honest_clients": hon_ids, "builder": "pafl.fl.variants.build_variant"},
        "quantisation": "x_hat = round(S * x), int64, within [-2^31, 2^31) on every channel (asserted); "
                        "the circuit adds a bias of 2^31 before hashing",
        "value_range_x_hat": value_range,
        "negative_channels": sorted(c for c, (lo, _) in value_range.items() if lo < 0),
        "batches": batches,
        "honest_pool_row_stats": honest_pool,
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "note": "SWaT telemetry: local only, never committed",
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(doc, open(out, "w"))
    log(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
