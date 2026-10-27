#!/usr/bin/env python3
"""Do the mined SWaT mass balances rest on each tank's own inflow and outflow? (Revision 1)

    python scripts/boundary_balances.py            -> results/boundary_balances.json

The miner (pafl.invariants.mine.mine_linear_balances, called by
pafl.data.swat.swat_invariants with alpha 5e-4 and at most 8 terms) regresses each
tank level's first difference on every flow meter of the plant. The balances it keeps
on SWaT therefore include flows outside the tank's own boundary, some with large
coefficients (stage-5 flows in the LIT101 balance, for example), and the LIT401
balance does not contain the tank's outflow meter at all. The paper's physical
reading is that the tank's own inflow and outflow carry the fit. This script tests
that reading: it refits each kept balance on the tank's inflow and outflow alone
(ordinary least squares with an intercept, on the same rows) and compares the
in-sample R^2 with the mined relation's. For reference it also fits the inflow alone,
and every flow meter by unpenalised least squares (an upper bound for any linear
balance on these rows). A near-constant outflow, like LIT401's RO feed (FIT401),
explains no variance on its own: its effect sits in the constant, and its coefficient
in a two-flow fit is not interpretable; `outflow_cv` reports how constant it is.

Rows and settings are those of every federated run: the fitting half of the
invariant slice (pafl.fl.scenario_real: the first 30 % of the normal record, split
in half; the other half calibrates the tolerances), and the miner thresholds of the
wide set (r2 0.40, off-ratio 0.10, support 0.005). R^2 is in-sample, as the miner
reports it.

Tank boundaries follow the SWaT process (stage 1 raw-water tank, stage 3 UF feed
tank, stage 4 RO feed tank):
    LIT101: in FIT101, out FIT201
    LIT301: in FIT201, out FIT301
    LIT401: in FIT301, out FIT401
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.data.real import load_real
from pafl.data.swat import swat_invariants
from pafl.fl.scenario_real import RealScenarioConfig
from pafl.invariants.mine import classify_channels, is_flow_tag, mine_linear_balances
from pafl.utils.paths import results_path

BOUNDARY = {"LIT101": ("FIT101", "FIT201"), "LIT301": ("FIT201", "FIT301"), "LIT401": ("FIT301", "FIT401")}
WIDE = dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005)


def r2_ols(X: np.ndarray, y: np.ndarray) -> tuple[float, np.ndarray]:
    """In-sample R^2 and coefficients (intercept first) of y on X by least squares."""
    A = np.column_stack([np.ones(len(X)), X])
    coef, *_ = np.linalg.lstsq(A, y, rcond=None)
    resid = y - A @ coef
    return 1.0 - float(np.sum(resid ** 2)) / (float(np.sum((y - y.mean()) ** 2)) + 1e-12), coef


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="results/boundary_balances.json")
    a = ap.parse_args()

    normal, _ = load_real("swat")
    cfg = RealScenarioConfig()
    inv_df = normal.iloc[: int(len(normal) * cfg.invariant_fraction)].reset_index(drop=True)
    fit_half = inv_df.iloc[: len(inv_df) // 2]          # as in pafl.fl.scenario_real.build_real_scenario

    _, report = swat_invariants(fit_half, **WIDE)
    kept = {b["tank"] for b in report["balances"]}
    mined = {r.target: r for r in mine_linear_balances(fit_half, alpha=5e-4, max_terms=8) if r.target in kept}
    cont, _ = classify_channels(fit_half)
    flows = [c for c in cont if is_flow_tag(c)]

    rows = {}
    for tank, (fin, fout) in BOUNDARY.items():
        if tank not in mined:
            rows[tank] = {"kept_by_miner": False}
            continue
        r = mined[tank]
        lvl = fit_half[tank].to_numpy(float)
        y = lvl[1:] - lvl[:-1]
        r2_b, coef_b = r2_ols(fit_half[[fin, fout]].to_numpy(float)[1:], y)
        r2_in, _ = r2_ols(fit_half[[fin]].to_numpy(float)[1:], y)
        q_out = fit_half[fout].to_numpy(float)
        r2_all, _ = r2_ols(fit_half[[f for f in flows if f != tank]].to_numpy(float)[1:], y)
        terms = dict(r.terms)
        rows[tank] = {
            "kept_by_miner": True, "inflow": fin, "outflow": fout,
            "mined_terms": {k: round(v, 4) for k, v in r.terms},
            "mined_r2": round(r.r2, 4),
            "boundary_r2": round(r2_b, 4),
            "boundary_coef": {fin: round(float(coef_b[1]), 4), fout: round(float(coef_b[2]), 4)},
            "inflow_only_r2": round(r2_in, 4),
            "outflow_cv": round(float(q_out.std() / (abs(q_out.mean()) + 1e-12)), 4),
            "all_flows_ols_r2": round(r2_all, 4),
            "boundary_flows_in_mined": [c for c in (fin, fout) if c in terms],
            "largest_mined_term": max(terms, key=lambda k: abs(terms[k])),
        }
    res = {"note": __doc__.strip().splitlines()[0], "rows": len(fit_half) - 1, "thresholds": WIDE, "tanks": rows}
    out = results_path(a.out)
    out.write_text(json.dumps(res, indent=2))

    print(f"fitting rows: {len(fit_half) - 1}\n{'tank':7s} {'mined R2':>9s} {'boundary R2':>12s} {'inflow R2':>10s} {'all flows':>10s}  boundary coef (in, out)  outflow cv  in mined fit       largest mined term")
    for tank, v in rows.items():
        if not v["kept_by_miner"]:
            print(f"{tank:7s} not kept by the miner"); continue
        bc = list(v["boundary_coef"].values())
        print(f"{tank:7s} {v['mined_r2']:9.4f} {v['boundary_r2']:12.4f} {v['inflow_only_r2']:10.4f} {v['all_flows_ols_r2']:10.4f}  "
              f"({bc[0]:+.3f}, {bc[1]:+.3f})        {v['outflow_cv']:9.3f}   {', '.join(v['boundary_flows_in_mined']) or '-':18s} {v['largest_mined_term']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
