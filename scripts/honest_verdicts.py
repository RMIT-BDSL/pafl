#!/usr/bin/env python3
"""The check's verdict on every honest client shard of the federated runs.

Criterion 1 measures the honest false-reject rate on 200 random 1,000-row
batches. The federated runs, until Sat 12 Sep, passed only malicious clients
through the check. This script rebuilds the federation of every (record,
invariant set, seed) the paper reports and records the verdict on each honest
shard, so the sentence "no honest client was rejected in any federated run" is
measured on the shards the detector actually trained on. Honest shards do not
depend on the attacker (fabrication, roll shift), so one build per seed covers
both attackers of a file.

    python scripts/honest_verdicts.py            -> results/honest_verdicts.json
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.fl.variants import build_variant
from pafl.utils.paths import results_path
from pafl.utils.logging import get_logger
from pafl.utils.seeds import set_seed

log = get_logger("honest_verdicts")

NARROW = dict(r2_min=0.60, coupling_off_ratio=0.05, coupling_support=0.02)
WIDE = dict(r2_min=0.40, coupling_off_ratio=0.10, coupling_support=0.005)

# (name, dataset, invariant kw, seeds, build kw) -- one row per adaptive result file family
CONFIGS = [
    ("swat_wide", "swat", WIDE, [0, 1, 2, 3, 4], dict(n_clients=10, malicious_fraction=0.3)),
    ("swat_narrow", "swat", NARROW, [0, 1, 2, 3, 4], dict(n_clients=10, malicious_fraction=0.3)),
    ("wadi_default", "wadi", NARROW, [0, 1, 2], dict(n_clients=10, malicious_fraction=0.3, target_attack_fraction=0.10)),
    ("batadal_mined", "batadal", NARROW, [0, 1, 2], dict(n_clients=5, malicious_fraction=0.3)),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", nargs="*", default=None, help="config names to run (default all)")
    ap.add_argument("--out", default="results/honest_verdicts.json")
    a = ap.parse_args()
    out = results_path(a.out)
    res = {"configs": {}, "note": __doc__.strip().splitlines()[0]}
    for name, dataset, inv_kw, seeds, kw in CONFIGS:
        if a.only and name not in a.only:
            continue
        rows = []
        for seed in seeds:
            set_seed(seed)
            t0 = time.time()
            sc, inv_set, _ = build_variant(dataset, "fabricated", kw["malicious_fraction"], kw["n_clients"],
                                           10, seed, fabrication="splice_only", invariant_kw=inv_kw,
                                           target_attack_fraction=kw.get("target_attack_fraction"))
            for v in sc["physics_verdicts"]:
                rows.append({"seed": seed, **v, "shard_rows": int(len(next(c for c in sc["clients"]
                                                                            if c.client_id == v["client"]).raw))})
            hon = [v for v in sc["physics_verdicts"] if not v["is_malicious"]]
            log.info("%s seed %d: %d honest shards, max violating %.4f, rejected %d (%.0fs)", name, seed,
                     len(hon), max(v["violating_fraction"] for v in hon), sum(not v["admitted"] for v in hon),
                     time.time() - t0)
        hon = [r for r in rows if not r["is_malicious"]]
        mal = [r for r in rows if r["is_malicious"]]
        res["configs"][name] = {
            "dataset": dataset, "invariant_kw": inv_kw, "seeds": seeds, "n_clients": kw["n_clients"],
            "n_invariants": len(inv_set),
            "honest_shards": len(hon), "honest_rejected": sum(not r["admitted"] for r in hon),
            "honest_violating_max": max(r["violating_fraction"] for r in hon),
            "honest_violating_mean": sum(r["violating_fraction"] for r in hon) / len(hon),
            "replay_batches": len(mal), "replay_admitted": sum(r["admitted"] for r in mal),
            "verdicts": rows,
        }
        json.dump(res, open(out, "w"), indent=1)
    print(f"\n{'config':14s} {'inv':>3s} {'honest shards':>13s} {'rejected':>8s} {'max viol':>9s} {'mean viol':>9s}  replay admitted")
    for name, c in res["configs"].items():
        print(f"{name:14s} {c['n_invariants']:3d} {c['honest_shards']:13d} {c['honest_rejected']:8d} "
              f"{c['honest_violating_max']:9.4f} {c['honest_violating_mean']:9.4f}  {c['replay_admitted']}/{c['replay_batches']}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
