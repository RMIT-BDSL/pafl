#!/usr/bin/env python3
"""Uncertainty and detector metrics for the adaptive-attacker results (Revision 1).

    python scripts/removal_stats.py                 -> results/removal_stats.json

Reads the adaptive files the paper reports and, without training, writes:

  removal    per file and aggregation rule, on targeted-attack recall: the damage
             removed by projection and by the gate (the same damage-weighted ratio as
             summarize_adaptive.removal, over the informative seeds, i.e. those where
             the naive attack did >= 1 point of damage against the seed's honest_only
             run), a seed-bootstrap 95% interval for each, and an exact one-sided
             Wilcoxon signed-rank test that gated (or projected) damage is below naive
             damage over the informative seeds.
  pooled     one paired test per invariant set over every informative
             (attacker, rule, seed) triple: Wilcoxon signed-rank and sign test,
             gated vs naive damage, and the pooled removal ratio.
  by_excluded  removal grouped by how many malicious clients the gate excluded in that
             seed (0-3). The gate's exclusions depend on the seed's projected batches,
             not on the rule, so this pools the rules.
  detector   mean and standard deviation over seeds of every stored detector metric
             (F1, precision, recall, F1-best, AUC-PR, targeted and untargeted recall)
             per file, rule and federation.

The bootstrap resamples informative seeds with replacement (10,000 draws, fixed RNG)
and recomputes the ratio; intervals are percentiles and are not clipped, so they can
pass 100% where gated runs landed above the reference within seed noise.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parents[1]
MODES = ("clean", "honest_only", "fabricated", "projected", "gated")
METRICS = ("f1", "precision", "recall", "f1_best", "auc_pr", "targeted_recall", "untargeted_recall")
MIN_DAMAGE = 0.01          # one point of recall, as summarize_adaptive.removal
N_BOOT = 10_000

# (name, invariant set, attacker, file) -- the files the paper's removal results read
FILES = [
    ("swat_wide_replay", "swat_wide", "replay", "swat_adaptive_wide_splice_20seed"),
    ("swat_wide_roll", "swat_wide", "roll", "swat_adaptive_wide_roll60_20seed"),
    ("swat_narrow_replay", "swat_narrow", "replay", "swat_adaptive_narrow_splice_20seed"),
    ("swat_narrow_roll", "swat_narrow", "roll", "swat_adaptive_narrow_roll60_20seed"),
    ("wadi_replay", "wadi_default", "replay", "wadi_adaptive_default_splice_3seed"),
    ("wadi_roll", "wadi_default", "roll", "wadi_adaptive_default_roll60_3seed"),
    ("batadal_replay", "batadal_mined", "replay", "batadal_adaptive_splice_3seed"),
    ("batadal_roll", "batadal_mined", "roll", "batadal_adaptive_roll_3seed"),
]


def cell_index(d: dict) -> dict:
    return {(c["seed"], c["defence"], c["mode"]): c for c in d["cells"].values()}


def defences_of(d: dict) -> list:
    out = []
    for c in d["cells"].values():
        if c["defence"] not in out:
            out.append(c["defence"])
    return out


def damage_rows(idx: dict, rule: str, seeds: list, field: str = "targeted_recall") -> list:
    """Per informative seed: (seed, naive damage, projected damage, gated damage, malicious excluded)."""
    rows = []
    for s in seeds:
        try:
            h, f, p, g = (idx[(s, rule, m)][field] for m in ("honest_only", "fabricated", "projected", "gated"))
        except KeyError:
            continue
        if h - f < MIN_DAMAGE:
            continue
        rows.append((s, h - f, h - p, h - g, idx[(s, rule, "gated")].get("n_malicious_excluded_by_gate")))
    return rows


def ratio(dn, dx) -> float:
    return float(1 - np.sum(dx) / np.sum(dn)) if len(dn) else float("nan")


def boot_ci(dn: np.ndarray, dx: np.ndarray, rng) -> list:
    if len(dn) < 2:
        return [float("nan"), float("nan")]
    i = rng.integers(0, len(dn), size=(N_BOOT, len(dn)))
    r = 1 - dx[i].sum(axis=1) / dn[i].sum(axis=1)
    return [float(np.percentile(r, 2.5)), float(np.percentile(r, 97.5))]


def wilcoxon_less(dn: np.ndarray, dx: np.ndarray) -> float | None:
    """One-sided exact p that dx (gated/projected damage) is below dn (naive damage)."""
    diff = dn - dx
    if len(diff) < 2 or np.all(diff == 0):
        return None
    return float(stats.wilcoxon(diff, alternative="greater", method="exact" if len(diff) <= 50 else "auto").pvalue)


def sign_test(dn: np.ndarray, dx: np.ndarray) -> dict:
    diff = dn - dx
    pos, neg = int((diff > 0).sum()), int((diff < 0).sum())
    p = float(stats.binomtest(pos, pos + neg, 0.5, alternative="greater").pvalue) if pos + neg else None
    return {"better": pos, "worse": neg, "tied": int(len(diff) - pos - neg), "p_one_sided": p}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "results" / "removal_stats.json"))
    a = ap.parse_args()
    rng = np.random.default_rng(0)
    res = {"note": __doc__.strip().splitlines()[0], "min_damage": MIN_DAMAGE, "n_boot": N_BOOT,
           "files": {}, "pooled": {}, "by_excluded": {}, "detector": {}}
    pooled: dict = {}
    for name, inv_set, attacker, fn in FILES:
        path = Path(a.results) / f"{fn}.json"
        if not path.exists():
            print(f"missing {path}", file=sys.stderr)
            continue
        d = json.load(open(path))
        idx = cell_index(d)
        seeds = sorted({k[0] for k in idx})
        rules = defences_of(d)
        per_rule = {}
        for rule in rules:
            rows = damage_rows(idx, rule, seeds)
            dn, dp, dg = (np.array([r[i] for r in rows]) for i in (1, 2, 3))
            per_rule[rule] = {
                "seeds": len(seeds), "informative": len(rows),
                "informative_seeds": [r[0] for r in rows],
                "naive_damage_mean": float(dn.mean()) if len(rows) else None,
                "removed_projection": ratio(dn, dp), "removed_projection_ci95": boot_ci(dn, dp, rng),
                "removed_gate": ratio(dn, dg), "removed_gate_ci95": boot_ci(dn, dg, rng),
                "wilcoxon_p_gate": wilcoxon_less(dn, dg), "wilcoxon_p_projection": wilcoxon_less(dn, dp),
                "per_seed": [{"seed": r[0], "dmg_naive": r[1], "dmg_projected": r[2], "dmg_gated": r[3],
                              "mal_excluded": r[4]} for r in rows],
            }
            for r in rows:
                pooled.setdefault(inv_set, []).append((attacker, rule) + r)
        res["files"][name] = {"file": fn, "invariant_set": inv_set, "attacker": attacker, "seeds": seeds,
                              "rules": per_rule}

        # removal against the number of malicious clients the gate excluded (pooled over rules)
        groups: dict = {}
        for rule in rules:
            for r in damage_rows(idx, rule, seeds):
                groups.setdefault(r[4], []).append(r)
        res["by_excluded"][name] = {
            str(k): {"pairs": len(v), "seeds": sorted({r[0] for r in v}),
                     "removed_gate": ratio(np.array([r[1] for r in v]), np.array([r[3] for r in v])),
                     "removed_projection": ratio(np.array([r[1] for r in v]), np.array([r[2] for r in v]))}
            for k, v in sorted(groups.items(), key=lambda kv: (kv[0] is None, kv[0]))}

        # detector-level metrics: mean and sd over seeds per rule and federation
        det = {}
        for rule in rules:
            det[rule] = {}
            for m in MODES:
                cs = [idx[(s, rule, m)] for s in seeds if (s, rule, m) in idx]
                if not cs:
                    continue
                det[rule][m] = {k: {"mean": float(np.mean([c[k] for c in cs if c.get(k) is not None])),
                                    "sd": float(np.std([c[k] for c in cs if c.get(k) is not None], ddof=1))
                                    if len(cs) > 1 else 0.0}
                                for k in METRICS if any(c.get(k) is not None for c in cs)}
                det[rule][m]["n"] = len(cs)
        res["detector"][name] = det

    for inv_set, rows in pooled.items():
        dn, dp, dg = (np.array([r[i] for r in rows]) for i in (3, 4, 5))
        res["pooled"][inv_set] = {
            "pairs": len(rows),
            "removed_gate": ratio(dn, dg), "removed_projection": ratio(dn, dp),
            "wilcoxon_p_gate": wilcoxon_less(dn, dg), "wilcoxon_p_projection": wilcoxon_less(dn, dp),
            "sign_gate": sign_test(dn, dg), "sign_projection": sign_test(dn, dp),
        }

    Path(a.out).write_text(json.dumps(res, indent=1))
    print(f"{'file':20s} {'rule':13s} {'inf':>6s} {'proj rm':>8s} {'95% CI':>17s} {'gate rm':>8s} {'95% CI':>17s} {'p gate':>8s}")
    for name, f in res["files"].items():
        for rule, r in f["rules"].items():
            if not r["informative"]:
                print(f"{name:20s} {rule:13s} {0:>3d}/{r['seeds']:<2d}  (no informative seed)")
                continue
            pc, gc = r["removed_projection_ci95"], r["removed_gate_ci95"]
            pg = r["wilcoxon_p_gate"]
            print(f"{name:20s} {rule:13s} {r['informative']:>3d}/{r['seeds']:<2d} {100*r['removed_projection']:7.1f}% "
                  f"[{100*pc[0]:6.1f},{100*pc[1]:6.1f}] {100*r['removed_gate']:7.1f}% [{100*gc[0]:6.1f},{100*gc[1]:6.1f}] "
                  f"{'' if pg is None else format(pg, '.4f'):>8s}")
    print("\npooled (gated vs naive):")
    for k, v in res["pooled"].items():
        print(f"  {k:14s} pairs {v['pairs']:3d}  gate removes {100*v['removed_gate']:.1f}%  projection {100*v['removed_projection']:.1f}%  "
              f"Wilcoxon p {v['wilcoxon_p_gate']:.2e}  sign {v['sign_gate']['better']}/{v['sign_gate']['worse']}/{v['sign_gate']['tied']}")
    print("\nremoval by malicious clients excluded (pooled over rules):")
    for name, g in res["by_excluded"].items():
        print(f"  {name:20s} " + "  ".join(f"{k} excl: {v['pairs']:3d} pairs, gate {100*v['removed_gate']:6.1f}%" for k, v in g.items()))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
