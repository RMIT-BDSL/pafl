#!/usr/bin/env python3
"""Per-attack coverage of an invariant set: which attacks can the physics gate see?

For every labelled attack segment in a real record, the fraction of its rows that
violate the mined invariants, under one or more miner settings. The paper's real-data
claim rests on this: the gate removes the poison that rides on physics the invariant
set covers, so coverage is the governing quantity and this table is its evidence.

    python scripts/coverage.py --dataset swat --out results/swat_coverage.json
    python scripts/coverage.py --dataset wadi --settings default --out results/wadi_coverage.json

Settings: narrow = miner defaults (r2 0.60, off-ratio 0.05, support 0.02);
          wide   = r2 0.40, off-ratio 0.10, support 0.005;
          default = the same thresholds as narrow, under the name the WADI files use.
Invariants are fitted and calibrated on the same clean slices the federation uses
(RealScenarioConfig.invariant_fraction), so the sets match the adaptive runs rule for
rule.

A segment is a contiguous run of rows labelled as attack at the loader's stride
(pafl.fl.scenario_real.attack_segments), not an entry in the dataset's attack list:
attacks that run back to back merge into one segment. A segment counts as covered when
more than --threshold of its rows violate an invariant. The default, 0.01, is the
admission rule's own bound (InvariantSet.batch_verdict), so "covered" means that a
batch made of that segment would be rejected.
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
from pafl.fl.scenario_real import attack_segments, RealScenarioConfig
from pafl.utils.paths import results_path

SETTINGS = {
    "narrow": dict(r2_min=0.60, coupling_off_ratio=0.05, coupling_support=0.02),
    "default": dict(r2_min=0.60, coupling_off_ratio=0.05, coupling_support=0.02),
    "wide": dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="swat", choices=["swat", "wadi", "batadal"])
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--settings", nargs="+", default=["narrow", "wide"])
    ap.add_argument("--threshold", type=float, default=0.01, help="a segment counts as covered above this violating fraction")
    ap.add_argument("--out", default=None)
    ap.add_argument("--latex", action="store_true", help="also print the summary rows as LaTeX")
    a = ap.parse_args()
    out = results_path(a.out or f"results/{a.dataset}_coverage.json")

    normal, attack = load_real(a.dataset, a.data_dir)
    cfg = RealScenarioConfig()
    n = len(normal); n_inv = int(n * cfg.invariant_fraction)
    fit = normal.iloc[: n_inv // 2]; cal = normal.iloc[n_inv // 2: n_inv]
    honest = normal.iloc[n_inv:]
    segs = attack_segments(attack)      # ATT_FLAG as the loader derives it from the file's own label column
    n_attack_rows = int(sum(len(s) for s in segs))

    sets = {}
    for name in a.settings:
        inv, rep = swat_invariants(fit, **SETTINGS[name]); inv.calibrate(cal)
        sets[name] = {"inv": inv, "report": rep,
                      # honest reference on the first 60,000 client-pool rows (~3.5 days at
                      # the loaders' 5 s stride), capped for speed
                      "honest_violating": float(inv.batch_verdict(honest.iloc[:60000])["violating_fraction"])}

    rows = []
    for k, s in enumerate(segs):
        sub = attack.iloc[s]
        row = {"segment": k, "rows": int(len(s)),
               "start": str(sub["datetime"].iloc[0]) if "datetime" in sub else None,
               "end": str(sub["datetime"].iloc[-1]) if "datetime" in sub else None}
        for name, S in sets.items():
            v = S["inv"].batch_verdict(sub)
            worst = max(v["per_invariant_violating_fraction"].items(), key=lambda kv: kv[1])
            row[name] = {"violating": round(v["violating_fraction"], 4),
                         "covered": bool(v["violating_fraction"] > a.threshold),
                         "worst_invariant": worst[0].split("::")[-1], "worst_fraction": round(worst[1], 4)}
        rows.append(row)

    summary = {}
    for name, S in sets.items():
        cov = [r for r in rows if r[name]["covered"]]
        summary[name] = {
            "n_invariants": len(S["inv"]), "couplings": S["report"]["kept_couplings"],
            "balances": S["report"]["kept_balances"], "thresholds": SETTINGS[name],
            "honest_violating_fraction": round(S["honest_violating"], 5),
            "segments_covered": len(cov), "segments_total": len(rows),
            "rows_covered": int(sum(r["rows"] for r in cov)), "rows_total": n_attack_rows,
            "rows_covered_share": round(sum(r["rows"] for r in cov) / max(n_attack_rows, 1), 4),
            "invariants": [i.name.split("::")[-1] for i in S["inv"]],
        }
    result = {"dataset": a.dataset, "coverage_threshold": a.threshold, "summary": summary, "segments": rows}
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    names = list(sets)
    print(f"\n{a.dataset}: {len(rows)} attack segments, {n_attack_rows} attack rows (at the loader's stride)\n")
    print(f"{'setting':8s} {'inv':>4s} {'coupl':>5s} {'bal':>4s} {'honest viol':>11s} {'segs covered':>13s} {'rows covered':>13s}")
    for name, S in summary.items():
        print(f"{name:8s} {S['n_invariants']:4d} {S['couplings']:5d} {S['balances']:4d} {S['honest_violating_fraction']:11.4f} "
              f"{S['segments_covered']:>6d}/{S['segments_total']:<6d} {S['rows_covered']:>6d}/{S['rows_total']:<6d} ({100*S['rows_covered_share']:.0f} %)")
    print()
    hdr = f"{'seg':>3s} {'rows':>5s} {'start':16s} " + " ".join(f"{n+' viol':>11s} {'worst':>14s}" for n in names)
    print(hdr)
    for r in sorted(rows, key=lambda r: -max(r[n]["violating"] for n in names)):
        cells = " ".join(f"{r[n]['violating']:11.3f} {r[n]['worst_invariant']:>14s}" for n in names)
        print(f"{r['segment']:3d} {r['rows']:5d} {(r['start'] or '')[5:16]:16s} {cells}")
    print(f"\nwrote {out}")

    if a.latex:
        print("\n% LaTeX: summary rows")
        for name, S in summary.items():
            print(f"{name} & {S['n_invariants']} & {S['couplings']}/{S['balances']} & {100*S['honest_violating_fraction']:.2f}\\% & "
                  f"{S['segments_covered']}/{S['segments_total']} & {100*S['rows_covered_share']:.0f}\\% \\\\")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
