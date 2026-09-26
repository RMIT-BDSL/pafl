#!/usr/bin/env python3
"""Step 1 of zk/PLAN.md: the mined invariant set in fixed point, for the circuit.

Rebuilds the invariant set exactly as the federation does (same clean slice,
same fit / calibrate halves, same miner thresholds), writes the affine
coefficients, constants and tolerances scaled by S = 2^16 to JSON, and checks
the integer model against the float one on the calibration half, on honest
batches and on channel-roll fabrications of them. The file holds no telemetry,
so it can be committed and shared; anyone with the SWaT archive regenerates it,
from the repo root, with

    .venv/bin/python zk/scripts/export_invariants.py --setting wide
    .venv/bin/python zk/scripts/export_invariants.py --setting narrow

The output should match the committed zk/data/invariants_swat_*.json except for
provenance.generated and provenance.pafl_commit, which record the date and commit
of the run. The circuit reads only the fixed-point fields; the float fields and
the checks block are there for audit.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from pafl.attacks.recipe_a import fabricate                       # noqa: E402
from pafl.data.loaders import feature_columns                     # noqa: E402
from pafl.data.real import load_real                              # noqa: E402
from pafl.data.swat import swat_invariants                        # noqa: E402
from pafl.fl.scenario_real import RealScenarioConfig              # noqa: E402
from pafl.zk.fixed_point import (fidelity, integer_verdict, quantise_invariants,  # noqa: E402
                                 quantise_rows)

# miner thresholds of the paper's two invariant sets (9 and 5 rules on SWaT); they must
# match the experiments' settings, and zk/lite/scripts/export_batches.py repeats them
SETTINGS = {
    "narrow": dict(r2_min=0.60, coupling_off_ratio=0.05, coupling_support=0.02),
    "wide": dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="swat", choices=["swat", "wadi"])
    ap.add_argument("--setting", default="wide", choices=sorted(SETTINGS))
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--scale-bits", type=int, default=16)
    ap.add_argument("--roll-shift", type=int, default=60, help="channel-roll shift for the parity check (rows)")
    ap.add_argument("--n-batches", type=int, default=50)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = Path(a.out) if a.out else ROOT / "zk" / "data" / f"invariants_{a.dataset}_{a.setting}.json"

    # --- the federation's own construction (pafl/fl/scenario_real.py) ---
    normal, _ = load_real(a.dataset, a.data_dir)
    cfg = RealScenarioConfig(**SETTINGS[a.setting])
    cols = [c for c in feature_columns(normal)
            if not any(p.upper() in str(c).upper() for p in cfg.exclude_channel_prefixes)]
    n = len(normal)
    n_inv = int(n * cfg.invariant_fraction)
    inv_df = normal.iloc[:n_inv].reset_index(drop=True)
    fit, cal = inv_df.iloc[: n_inv // 2], inv_df.iloc[n_inv // 2:].reset_index(drop=True)
    pool = normal.iloc[n_inv:].reset_index(drop=True)
    inv_set, report = swat_invariants(fit, max_invariants=cfg.max_invariants, r2_min=cfg.r2_min,
                                      coupling_off_ratio=cfg.coupling_off_ratio,
                                      coupling_support=cfg.coupling_support)
    inv_set.calibrate(cal)

    q = quantise_invariants(inv_set, cal, cols, scale_bits=a.scale_bits, report=report)

    # --- checks: the integer model against the float one ---
    checks = {"calibration_half": fidelity(inv_set, cal, cols, q)}
    # fixed seed: the 50 parity batches are the same on every run
    rs = np.random.default_rng(0)
    rows = 1000
    parity = {"honest": [0, 0], "channel_roll": [0, 0]}
    disagree = []
    honest_int, honest_float = [], []
    for b in range(a.n_batches):
        i = int(rs.integers(1, len(pool) - rows))
        batch = pool.iloc[i:i + rows].reset_index(drop=True)
        rolled = fabricate(batch, "channel_roll", seed=b, shift=a.roll_shift)
        for kind, df in (("honest", batch), ("channel_roll", rolled)):
            vf = inv_set.batch_verdict(df)
            vi = integer_verdict(quantise_rows(df, cols, q["S"]), q)
            parity[kind][1] += 1
            parity[kind][0] += int(vf["admitted"] == vi["admitted"])
            if vf["admitted"] != vi["admitted"]:
                disagree.append({"batch": b, "kind": kind, "float": vf["violating_fraction"],
                                 "integer": vi["violating_fraction"]})
            if kind == "honest":
                honest_float.append(vf["violating_fraction"]); honest_int.append(vi["violating_fraction"])
    checks["batch_verdict_parity"] = {k: {"agree": v[0], "of": v[1]} for k, v in parity.items()}
    checks["batch_verdict_disagreements"] = disagree
    checks["honest_batches"] = {"n": a.n_batches, "rows": rows,
                                "float_violating_mean": float(np.mean(honest_float)),
                                "integer_violating_mean": float(np.mean(honest_int)),
                                # 0.01 is the batch gate's admission threshold (integer_verdict's default)
                                "integer_false_reject_rate": float(np.mean([f > 0.01 for f in honest_int]))}
    na = inv_set.batch_verdict(cal)["not_applicable_fraction"]
    checks["not_applicable_fraction_on_calibration_half"] = na

    try:
        commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        commit = None
    q["provenance"] = {
        "dataset": a.dataset, "setting": a.setting, "miner_thresholds": SETTINGS[a.setting],
        "construction": "pafl.fl.scenario_real.RealScenarioConfig: first 30 % of the normal record is the invariant slice; "
                        "fitted on its first half, tolerances calibrated on its second half (1.5 x the 99.9th percentile of |r|)",
        "rows": {"normal_record": int(n), "fit": int(len(fit)), "calibrate": int(len(cal)), "client_pool": int(len(pool))},
        "excluded_channel_prefixes": list(cfg.exclude_channel_prefixes),
        "mining_report": report,
        "generated": dt.date.today().isoformat(), "pafl_commit": commit,
        "script": "zk/scripts/export_invariants.py",
    }
    q["checks"] = checks
    q["budgets"] = {"v_max": None, "u_max": None,
                    "note": "violation and inapplicability budgets per k are chosen by the circuit designer; "
                            "the honest violating rate and per-rule not-applicable fractions above size them"}
    out.parent.mkdir(parents=True, exist_ok=True)
    json.dump(q, open(out, "w"), indent=1)

    c = checks["calibration_half"]
    print(f"{a.dataset} {a.setting}: {q['n_invariants']} invariants over {len(q['channels_touched'])} of {len(cols)} channels; S = 2^{a.scale_bits}")
    for inv in q["invariants"]:
        print(f"  {inv['name']:28s} eps {inv['eps']:.5g}  eps_hat {inv['eps_hat']:>12d}  terms prev/cur {len(inv['coef_prev'])}/{len(inv['coef_cur'])}")
    print(f"fidelity on {c['rows']} calibration rows: max residual error {c['residual_error_max_over_eps']:.2e} eps, "
          f"applicability disagreements {c['applicability_disagreements']}/{c['cells']}, violation disagreements {c['violation_disagreements']}/{c['cells']}; "
          f"violating fraction float {c['float_violating_fraction']:.5f} vs integer {c['integer_violating_fraction']:.5f}")
    print(f"batch verdict parity: honest {parity['honest'][0]}/{parity['honest'][1]}, channel roll {parity['channel_roll'][0]}/{parity['channel_roll'][1]}; "
          f"integer honest false-reject {checks['honest_batches']['integer_false_reject_rate']:.3f}")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
