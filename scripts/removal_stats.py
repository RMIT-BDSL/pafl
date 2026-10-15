#!/usr/bin/env python3
"""Uncertainty and detector metrics for the adaptive-attacker results (Revision 1).

    python scripts/removal_stats.py                 -> results/removal_stats.json

Reads the adaptive files the paper reports and, without training, writes:

  removal    per file and aggregation rule, on targeted-attack recall: the damage
             removed by projection and by the gate (the same damage-weighted ratio as
             summarize_adaptive.removal, over the informative seeds, i.e. those where
             the naive attack did >= 1 point of damage against the seed's reference
             run), a seed-bootstrap 95% interval for each, and exact one-sided
             Wilcoxon signed-rank tests over the informative seeds: gated (or
             projected) damage below naive damage, and gated below projected damage
             (does the gate add anything beyond projection). The reference is the
             seed's honest_only run, or its clean run when a file has no honest_only
             mode (the BATADAL files), as in summarize_adaptive.
  pooled     per invariant set, with the seed as the unit: the rules and attackers of
             one seed share its projected batches and the gate's exclusions, so their
             (rule, seed) pairs are not independent. Damage is summed per seed over
             the informative (attacker, rule) pairs; the tests are exact one-sided
             Wilcoxon signed-rank tests over seeds (gate vs naive, projection vs
             naive, gate vs projection) and the intervals resample seeds. Reported for
             all rules and for the five rules without Krum and FoolsGold (Krum never
             accepts a malicious update, so its "damage" is composition: which honest
             update it selects when ten rather than seven clients are present).
  by_excluded  removal grouped by how many malicious clients the gate excluded in that
             seed (0-3). The gate's exclusions depend on the seed's projected batches,
             not on the rule, so this pools the rules.
  detector   mean and standard deviation over seeds of every stored detector metric
             (F1, precision, recall, F1-best, AUC-PR, targeted and untargeted recall)
             per file, rule and federation.

The bootstrap resamples informative seeds with replacement (100,000 draws, fixed RNG)
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
N_BOOT = 100_000           # endpoints stable to < 1 point across RNG seeds (10,000 moved them up to 3)
CORE = ("fedavg", "median", "trimmed_mean", "norm_clip", "fltrust")

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


def reference_mode(idx: dict) -> str:
    """honest_only (the same honest shards without the attacker), else clean."""
    return "honest_only" if any(k[2] == "honest_only" for k in idx) else "clean"


def damage_rows(idx: dict, rule: str, seeds: list, field: str = "targeted_recall") -> list:
    """Per informative seed: (seed, naive damage, projected damage, gated damage, malicious excluded)."""
    ref = reference_mode(idx)
    rows = []
    for s in seeds:
        missing = [m for m in (ref, "fabricated", "projected", "gated") if (s, rule, m) not in idx]
        if missing:
            raise KeyError(f"seed {s} rule {rule}: no {missing} cell")
        h, f, p, g = (idx[(s, rule, m)][field] for m in (ref, "fabricated", "projected", "gated"))
        if h - f < MIN_DAMAGE:
            continue
        gc = idx[(s, rule, "gated")]           # files from before the honest/malicious split record only the total
        rows.append((s, h - f, h - p, h - g, gc.get("n_malicious_excluded_by_gate", gc.get("n_excluded_by_gate"))))
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
    """One-sided exact p that dx is below dn, paired (zero differences dropped).

    Checked against brute-force enumeration of the sign assignments with mid-ranks."""
    diff = dn - dx
    if len(diff) < 2 or np.all(diff == 0):
        return None
    return float(stats.wilcoxon(diff, alternative="greater", method="exact").pvalue)


def seed_boot_ci(per_seed: np.ndarray, rng) -> list:
    """95% interval of the pooled removal 1 - sum(dx)/sum(dn), resampling seeds; per_seed = [[dn, dx], ...]."""
    if len(per_seed) < 2:
        return [float("nan"), float("nan")]
    i = rng.integers(0, len(per_seed), size=(N_BOOT, len(per_seed)))
    r = 1 - per_seed[i, 1].sum(axis=1) / per_seed[i, 0].sum(axis=1)
    return [float(np.percentile(r, 2.5)), float(np.percentile(r, 97.5))]


def fmt_p(p: float | None) -> str:
    return "n/a" if p is None else f"{p:.1e}"


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
                "wilcoxon_p_gate_vs_projection": wilcoxon_less(dp, dg),
                "per_seed": [{"seed": r[0], "dmg_naive": r[1], "dmg_projected": r[2], "dmg_gated": r[3],
                              "mal_excluded": r[4]} for r in rows],
            }
            for r in rows:
                pooled.setdefault(inv_set, []).append((attacker, rule) + r)
        res["files"][name] = {"file": fn, "invariant_set": inv_set, "attacker": attacker, "seeds": seeds,
                              "reference": reference_mode(idx), "rules": per_rule}

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
        res["pooled"][inv_set] = {}
        for label, keep in (("all_rules", None), ("without_krum_foolsgold", CORE)):
            sel = [r for r in rows if keep is None or r[1] in keep]
            seeds = sorted({r[2] for r in sel})
            S = np.array([[sum(r[k] for r in sel if r[2] == s) for k in (3, 4, 5)] for s in seeds])   # dn, dp, dg per seed
            dn, dp, dg = S[:, 0], S[:, 1], S[:, 2]
            res["pooled"][inv_set][label] = {
                "pairs": len(sel), "seeds": len(seeds), "unit": "seed",
                "removed_gate": ratio(dn, dg), "removed_gate_ci95": seed_boot_ci(S[:, [0, 2]], rng),
                "removed_projection": ratio(dn, dp), "removed_projection_ci95": seed_boot_ci(S[:, [0, 1]], rng),
                "wilcoxon_p_gate": wilcoxon_less(dn, dg), "wilcoxon_p_projection": wilcoxon_less(dn, dp),
                "wilcoxon_p_gate_vs_projection": wilcoxon_less(dp, dg),
                "seeds_gate_better": int((dg < dn).sum()), "seeds_gate_beyond_projection": int((dg < dp).sum()),
                "pairs_sign_gate": sign_test(np.array([r[3] for r in sel]), np.array([r[5] for r in sel])),
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
    print("\npooled, seed as the unit (exact Wilcoxon over seeds; intervals resample seeds):")
    for k, by in res["pooled"].items():
        for lab, v in by.items():
            gc, pc = v["removed_gate_ci95"], v["removed_projection_ci95"]
            print(f"  {k:14s} {lab:23s} {v['pairs']:3d} pairs / {v['seeds']:2d} seeds  gate {100*v['removed_gate']:5.1f}% [{100*gc[0]:5.1f},{100*gc[1]:5.1f}]"
                  f"  projection {100*v['removed_projection']:5.1f}% [{100*pc[0]:5.1f},{100*pc[1]:5.1f}]"
                  f"  p gate {fmt_p(v['wilcoxon_p_gate'])}  p gate>proj {fmt_p(v['wilcoxon_p_gate_vs_projection'])}")
    print("\nremoval by malicious clients excluded (pooled over rules):")
    for name, g in res["by_excluded"].items():
        print(f"  {name:20s} " + "  ".join(f"{k} excl: {v['pairs']:3d} pairs, gate {100*v['removed_gate']:6.1f}%" for k, v in g.items()))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
