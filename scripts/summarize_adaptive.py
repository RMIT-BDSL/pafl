#!/usr/bin/env python3
"""Print the three-federation comparison from one or more day45 result files.

For every defence: clean / fabricated / projected, as global F1 and, where the
scenario defines a target set (real data), as recall on the targeted attacks
and on the other attacks. Also the two doors: the share of malicious updates the
aggregation rule accepted, and the share of malicious batches the physics check
admitted (before projection in the fabricated column, after it in the
projected column). Per-seed rows follow the mean so a single seed cannot hide.
"""
from __future__ import annotations
import argparse
import json
import sys
from collections import defaultdict

import numpy as np


def load(path):
    with open(path) as f:
        return json.load(f)


def removal(dfn, field, seeds, get, min_damage=0.01):
    """(removed by projection, removed by gate, seeds used), damage-weighted."""
    df_sum = dp_sum = dg_sum = 0.0
    n = 0
    for s in seeds:
        c, h, f, p, g = (get(dfn, m, field, s) for m in ("clean", "honest_only", "fabricated", "projected", "gated"))
        # the fair reference is the same honest shards without the attacker
        # (honest_only); fall back to the ten-honest clean run when absent
        if not np.isnan(h):
            c = h
        if np.isnan(c) or np.isnan(f) or c - f < min_damage:
            continue
        n += 1
        df_sum += c - f
        dp_sum += (c - p) if not np.isnan(p) else (c - f)
        dg_sum += (c - g) if not np.isnan(g) else float("nan")
    if n == 0:
        return float("nan"), float("nan"), 0
    return 1 - dp_sum / df_sum, 1 - dg_sum / df_sum, n


def table(d, name):
    cells = list(d["cells"].values())
    defences = []
    for c in cells:
        if c["defence"] not in defences:
            defences.append(c["defence"])
    seeds = sorted({c["seed"] for c in cells})
    modes = ("clean", "honest_only", "fabricated", "projected", "gated")
    args = d.get("args", {})
    print(f"\n=== {name} ===")
    print(f"dataset={args.get('dataset')} fabrication={args.get('fabrication')} "
          f"roll_shift={args.get('roll_shift')} r2_min={args.get('r2_min')} "
          f"off={args.get('coupling_off_ratio')} sup={args.get('coupling_support')} "
          f"seeds={seeds} clients={args.get('clients')} rounds={args.get('rounds')}")

    def get(defence, mode, field, seed=None):
        vals = [c.get(field) for c in cells if c["defence"] == defence and c["mode"] == mode
                and (seed is None or c["seed"] == seed) and c.get(field) is not None]
        return float(np.mean(vals)) if vals else float("nan")

    has_t = any(c.get("targeted_recall") is not None for c in cells)
    hdr = f"{'defence':<13s} {'metric':<18s} {'clean':>8s} {'honest7':>8s} {'fabric.':>8s} {'project.':>8s} {'gated':>8s} {'removed':>9s} {'gated rm':>9s}"
    print(hdr)
    for dfn in defences:
        for label, field in (("F1", "f1"),) + ((("targeted recall", "targeted_recall"),
                                                 ("untargeted recall", "untargeted_recall")) if has_t else ()):
            c, ho, fb, pj, gt = (get(dfn, m, field) for m in modes)
            # Removal is aggregated over the seeds in which the naive attack did
            # at least one point of damage, weighting each seed by that damage.
            # A seed with no damage has nothing to remove, and a gated run that
            # excluded clients is a different federation whose baseline shift
            # would otherwise be counted as "removal".
            rem, remg, n_used = removal(dfn, field, seeds, get)
            flag = "" if n_used else "  (no seed with >= 1 pt naive damage; ratio not meaningful)"
            if label == "F1":
                ref = "honest_only" if not np.isnan(ho) else "clean"
                print(f"{dfn:<13s} {'(reference: ' + ref + ')':<18s}")
            print(f"{dfn:<13s} {label:<18s} {c:8.4f} {ho:8.4f} {fb:8.4f} {pj:8.4f} {gt:8.4f} {100*rem:8.1f}% {100*remg:8.1f}%"
                  f"{'' if not n_used else f'  [{n_used}/{len(seeds)} seeds]'}{flag}")
            if len(seeds) > 1 and field in ("f1", "targeted_recall"):
                for s in seeds:
                    cs, hs, fs, ps, gs = (get(dfn, m, field, s) for m in modes)
                    print(f"{'':<13s} {'  seed '+str(s):<18s} {cs:8.4f} {hs:8.4f} {fs:8.4f} {ps:8.4f} {gs:8.4f}")
        acc_f, acc_p, acc_g = (get(dfn, m, "malicious_acceptance_rate") for m in ("fabricated", "projected", "gated"))
        ph_f, ph_p = get(dfn, "fabricated", "physics_admitted_rate"), get(dfn, "projected", "physics_admitted_rate")
        exc = get(dfn, "gated", "n_excluded_by_gate")
        print(f"{dfn:<13s} {'rule accepts mal.':<18s} {'':>8s} {'':>8s} {acc_f:8.2f} {acc_p:8.2f} {acc_g:8.2f}")
        print(f"{dfn:<13s} {'physics admits':<18s} {'':>8s} {'':>8s} {ph_f:8.2f} {ph_p:8.2f} {'excl. '+format(exc, '.1f') if not np.isnan(exc) else '':>8s}")
    if d.get("projection"):
        sh = [p["mean_abs_shift_sigma"] for p in d["projection"]]
        va = [p["violating_after"] for p in d["projection"]]
        print(f"projection: mean shift {np.mean(sh):.4f} sigma, violating after {np.mean(va):.4f}, "
              f"{len(sh)} batches")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    for f in a.files:
        try:
            table(load(f), f)
        except FileNotFoundError:
            print(f"\n=== {f} === (missing)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
