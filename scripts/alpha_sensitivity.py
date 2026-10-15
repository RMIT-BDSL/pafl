#!/usr/bin/env python3
"""Sensitivity of the results to the admission threshold alpha (Revision 1).

    python scripts/alpha_sensitivity.py             -> results/alpha_sensitivity.json

alpha is the largest fraction of a batch's rows that may break an invariant before the
batch is rejected (1% in the paper). For alpha in {0.5, 1, 2, 5}% this collects,
without training:

  honest     honest client shards rejected, per invariant set (honest_verdicts.json:
             a shard is rejected when its violating fraction exceeds alpha)
  coverage   labelled attack segments covered, SWaT narrow / wide and WADI
             ({swat,wadi}_coverage.json: covered when more than alpha of the
             segment's rows violate)
  projected  physics-aware batches the gate admits after projection, SWaT wide
             (the projection entries of the adaptive files; the attacker's 0.5%
             target is the same at every alpha, so the batches are the same)
  removal    per rule and attacker, SWaT wide: the damage removed by the gate, from
             the gated federations rerun at that alpha (the *_alpha*.json files; the
             1% runs are the headline files). The honest_only, naive and
             physics-aware federations do not depend on alpha, so the reference,
             the naive damage and the informative seeds come from the headline
             files. Also the honest and malicious clients the gate excluded.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
ALPHAS = [0.005, 0.01, 0.02, 0.05]
MIN_DAMAGE = 0.01
ATTACKERS = {"replay": "swat_adaptive_wide_splice_20seed", "roll": "swat_adaptive_wide_roll60_20seed"}


def tag(alpha: float) -> str:
    return "" if alpha == 0.01 else "_alpha" + f"{alpha:g}".replace(".", "p")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", default=str(ROOT / "results"))
    ap.add_argument("--out", default=str(ROOT / "results" / "alpha_sensitivity.json"))
    a = ap.parse_args()
    R = Path(a.results)
    load = lambda n: json.load(open(R / f"{n}.json"))
    res = {"note": __doc__.strip().splitlines()[0], "alphas": ALPHAS, "min_damage": MIN_DAMAGE,
           "honest": {}, "coverage": {}, "projected": {}, "removal": {}}

    hv = load("honest_verdicts")["configs"]
    for name, c in hv.items():
        hon = [v["violating_fraction"] for v in c["verdicts"] if not v["is_malicious"]]
        res["honest"][name] = {"shards": len(hon),
                               "rejected": {str(al): int(sum(f > al for f in hon)) for al in ALPHAS}}

    for ds in ("swat", "wadi"):
        cov = load(f"{ds}_coverage")
        sets = [k for k in cov["summary"]]
        res["coverage"][ds] = {s: {"segments": len(cov["segments"]),
                                   "covered": {str(al): int(sum(seg[s]["violating"] > al for seg in cov["segments"]))
                                               for al in ALPHAS}} for s in sets}

    for atk, base_fn in ATTACKERS.items():
        base = load(base_fn)
        # one batch per (seed, client): the projection is the same for every rule and mode
        batches = {(p["seed"], p["client"]): p["violating_after"] for p in base["projection"]}
        res["projected"][atk] = {"batches": len(batches),
                                 "admitted": {str(al): int(sum(v <= al for v in batches.values())) for al in ALPHAS}}

        bidx = {(c["seed"], c["defence"], c["mode"]): c for c in base["cells"].values()}
        rules = list(dict.fromkeys(c["defence"] for c in base["cells"].values()))
        seeds = sorted({c["seed"] for c in base["cells"].values()})
        out = {}
        for al in ALPHAS:
            fn = base_fn + tag(al)
            if not (R / f"{fn}.json").exists():
                continue
            gidx = {(c["seed"], c["defence"]): c for c in load(fn)["cells"].values() if c["mode"] == "gated"}
            per_rule = {}
            for rule in rules:
                dn = dp = dg = 0.0
                inf = []
                for s in seeds:
                    h, f, p = (bidx[(s, rule, m)]["targeted_recall"] for m in ("honest_only", "fabricated", "projected"))
                    if h - f < MIN_DAMAGE or (s, rule) not in gidx:
                        continue
                    inf.append(s)
                    dn += h - f
                    dp += h - p
                    dg += h - gidx[(s, rule)]["targeted_recall"]
                g_all = [gidx[(s, rule)] for s in seeds if (s, rule) in gidx]
                per_rule[rule] = {
                    "informative": len(inf),
                    "removed_gate": 1 - dg / dn if inf else None,
                    "removed_projection": 1 - dp / dn if inf else None,
                    "mal_excluded_mean": float(np.mean([c["n_malicious_excluded_by_gate"] for c in g_all])),
                    "honest_excluded_mean": float(np.mean([c["n_honest_excluded_by_gate"] for c in g_all])),
                    "honest_excluded_runs": int(sum(c["n_honest_excluded_by_gate"] > 0 for c in g_all)),
                    "runs": len(g_all),
                }
            out[str(al)] = {"file": fn, "rules": per_rule}
        res["removal"][atk] = out

    Path(a.out).write_text(json.dumps(res, indent=1))

    print("honest shards rejected:", "  ".join(f"{n} " + "/".join(str(c["rejected"][str(al)]) for al in ALPHAS)
                                               + f" of {c['shards']}" for n, c in res["honest"].items()),
          f"   (alpha = {', '.join(f'{100*x:g}%' for x in ALPHAS)})")
    for ds, sets in res["coverage"].items():
        for s, c in sets.items():
            print(f"coverage {ds} {s}: " + " / ".join(str(c["covered"][str(al)]) for al in ALPHAS) + f" of {c['segments']}")
    for atk, c in res["projected"].items():
        print(f"projected {atk} admitted: " + " / ".join(str(c["admitted"][str(al)]) for al in ALPHAS) + f" of {c['batches']}")
    for atk, by_al in res["removal"].items():
        print(f"\ngate removal, SWaT wide, {atk}  (projection only | alpha " + " ".join(f"{100*float(x):g}%" for x in by_al) + ")")
        rules = next(iter(by_al.values()))["rules"]
        for rule in rules:
            r0 = rules[rule]
            row = "  ".join(("   n/a" if by_al[x]["rules"][rule]["removed_gate"] is None
                             else f"{100*by_al[x]['rules'][rule]['removed_gate']:6.1f}") for x in by_al)
            pr = r0["removed_projection"]
            print(f"  {rule:13s} inf {r0['informative']:2d}  {'   n/a' if pr is None else format(100*pr, '6.1f')} | {row}")
        print("  malicious excluded / run: " + "  ".join(f"{100*float(x):g}%: {np.mean([r['mal_excluded_mean'] for r in by_al[x]['rules'].values()]):.2f}" for x in by_al))
        print("  runs with an honest client excluded: " + "  ".join(f"{100*float(x):g}%: {sum(r['honest_excluded_runs'] for r in by_al[x]['rules'].values())}/{sum(r['runs'] for r in by_al[x]['rules'].values())}" for x in by_al))
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
