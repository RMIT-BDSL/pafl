#!/usr/bin/env python3
"""A LaTeX table from one adaptive.py result file, for inspection. No number is typed by hand.

    python scripts/tables.py results/swat_adaptive_wide_splice_5seed.json --metric targeted_recall

Prints a booktabs table with one row per aggregation rule. The columns are clean /
honest_only / fabricated (naive) / projected (physics-aware) / gated, each the mean
over seeds with min–max in small type; then the damage removed by projection and by
the gate, with the same rule as summarize_adaptive.py; then the two doors (the share
of malicious updates the rule accepted, and the share of malicious batches the check
admitted after projection).

The paper's typeset tables were generated separately, from the same JSON files and
with the same removal rule; this script is a quick equivalent for checking a file.
"""
from __future__ import annotations
import argparse
import json

import numpy as np

NICE = {"fedavg": "FedAvg", "krum": "Krum", "median": "Median", "trimmed_mean": "Trimmed mean",
        "norm_clip": "Norm clip", "fltrust": "FLTrust", "foolsgold": "FoolsGold"}
MODES = ("clean", "honest_only", "fabricated", "projected", "gated")


def cell(vals):
    """Mean over seeds, with the min–max range when there is more than one seed."""
    if not vals:
        return "--"
    m = float(np.mean(vals))
    if len(vals) > 1:
        return f"{m:.3f}\\,{{\\scriptsize({min(vals):.2f}–{max(vals):.2f})}}"
    return f"{m:.3f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--metric", default="targeted_recall", choices=["targeted_recall", "f1", "auc_pr"])
    ap.add_argument("--caption", default=None)
    a = ap.parse_args()
    d = json.load(open(a.file))
    cells = list(d["cells"].values())
    defences = [x for x in NICE if any(c["defence"] == x for c in cells)]
    args = d.get("args", {})

    def vals(dfn, mode, field):
        return [c[field] for c in cells if c["defence"] == dfn and c["mode"] == mode
                and c.get(field) is not None]

    lines = []
    lines.append("\\begin{table}[t]\\centering\\scriptsize")
    cap = a.caption or (f"{args.get('dataset')}, {args.get('fabrication')}"
                        + (f" (shift {args.get('roll_shift')})" if args.get('roll_shift') else "")
                        + f", {len({c['seed'] for c in cells})} seeds, {args.get('clients')} clients, "
                        f"{args.get('rounds')} rounds; metric: {a.metric.replace('_', ' ')}.")
    lines.append(f"\\caption{{{cap}}}")
    lines.append("\\begin{tabular}{@{}l ccccc rr cc@{}}\\toprule")
    lines.append("Rule & Honest & Na\\\"ive & Physics-aware & Gated & Removed (proj.) & Removed (gate) & Rule admits & Check admits\\\\\\midrule")
    for dfn in defences:
        v = {m: vals(dfn, m, a.metric) for m in MODES}
        # damage-weighted removal over seeds with >= 1 pt naive damage (see summarize_adaptive.py)
        seeds = sorted({c["seed"] for c in cells})
        df_sum = dp_sum = dg_sum = 0.0; n_used = 0
        for sd in seeds:
            per = {m: [c[a.metric] for c in cells if c["defence"] == dfn and c["mode"] == m
                       and c["seed"] == sd and c.get(a.metric) is not None] for m in MODES}
            if not per["clean"] or not per["fabricated"]:
                continue
            ref = per["honest_only"][0] if per["honest_only"] else per["clean"][0]
            c_, f_ = ref, per["fabricated"][0]
            if c_ - f_ < 0.01:
                continue
            n_used += 1; df_sum += c_ - f_
            dp_sum += (c_ - per["projected"][0]) if per["projected"] else (c_ - f_)
            dg_sum += (c_ - per["gated"][0]) if per["gated"] else float("nan")
        rem_p = 100 * (1 - dp_sum / df_sum) if n_used else float("nan")
        rem_g = 100 * (1 - dg_sum / df_sum) if n_used else float("nan")
        small = n_used == 0
        fmt = lambda x: ("--" if np.isnan(x) else f"{x:.0f}\\%" + (f"\\,{{\\scriptsize[{n_used}/{len(seeds)}]}}" if n_used < len(seeds) else ""))
        acc = vals(dfn, "projected", "malicious_acceptance_rate")
        adm = vals(dfn, "projected", "physics_admitted_rate")
        lines.append(f"{NICE[dfn]} & {cell(v['clean'])} & {cell(v['honest_only'])} & {cell(v['fabricated'])} & {cell(v['projected'])} & "
                     f"{cell(v['gated'])} & {fmt(rem_p)} & {fmt(rem_g)} & "
                     f"{np.mean(acc):.2f} & {np.mean(adm) if adm else float('nan'):.2f}\\\\")
    lines.append("\\bottomrule\\end{tabular}")
    lines.append("\\vspace{2pt}\\\\{\\scriptsize Removed = share of the na\\\"ive attack's damage that does not "
                 "survive; in parentheses where the na\\\"ive damage is under one point. Ranges are min–max over seeds.}")
    lines.append("\\end{table}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
