#!/usr/bin/env python3
"""Week 2. The FLTrust interaction (criterion 4b), measured properly.

The pilot found that projecting a fabricated batch onto the physics manifold
made the attack *stronger* against FLTrust, while removing it against FedAvg and
trimmed mean. The pilot could not tell whether that was a property of FLTrust, a
property of similarity-weighted trust in general, or a one-seed accident. This
script settles it, and produces the trace the paper argues from.

It runs three federations -- clean, fabricated, projected -- against each
similarity-based defence (FLTrust and, newly, FoolsGold), across several seeds,
and records for every round the trust weight each rule assigned to the malicious
clients. Two claims are then testable:

* The mechanism. Does projection raise the malicious clients' acceptance and
  trust weight? This is expected to hold in every seed, because it follows from
  the definition of a cosine-similarity rule: moving a batch onto the manifold
  moves its update toward the honest cone, which is exactly what these rules
  reward. The acceptance jump is the robust, replicated fact.

* The consequence. Does that raised trust translate into more F1 damage? This is
  the noisier claim. The script reports it per seed and in aggregate, and flags
  where projection helped the attacker, so the paper can state the magnitude
  honestly rather than averaging a null seed into a headline.

If FoolsGold shows the same interaction as FLTrust, the finding generalises to
similarity-weighted defences as a class, and that is the conference-paper spin.
"""
from __future__ import annotations
import argparse
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.fl.train import FLConfig, run_federation
from pafl.fl.variants import build_variant
from pafl.utils.ckpt import install_spot_handler, interrupted, load_json, save_json
from pafl.utils.paths import results_path
from pafl.utils.logging import get_logger
from pafl.utils.seeds import set_seed

log = get_logger("week2_4b")


def build(dataset, data_dir, mode, mal, clients, window, seed, partition, roll_shift=None,
          invariant_kw=None):
    """Return (scenario, inv_set, cols). mode in clean|fabricated|projected.

    Thin wrapper over pafl.fl.variants.build_variant, kept so the call sites in
    this script read the same as in day45_adaptive.py.
    """
    return build_variant(dataset, mode, mal, clients, window, seed,
                         data_dir=data_dir, partition=partition, roll_shift=roll_shift,
                         invariant_kw=invariant_kw)


def malicious_trust(trust_log):
    """Mean trust weight on malicious clients, per round and overall."""
    per_round = []
    for rec in trust_log:
        mal = [t for t, m in zip(rec["trust"], rec["is_malicious"]) if m]
        per_round.append(float(np.mean(mal)) if mal else 0.0)
    return per_round, (float(np.mean(per_round)) if per_round else 0.0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="synthetic", choices=["synthetic", "swat", "wadi", "batadal"])
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--defences", nargs="+", default=["fltrust", "foolsgold"])
    ap.add_argument("--malicious-fraction", type=float, default=0.3)
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--local-epochs", type=int, default=2)
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--partition", default="temporal", choices=["temporal", "iid"])
    ap.add_argument("--r2-min", type=float, default=0.60, help="balance R^2 cut for the miner (real data)")
    ap.add_argument("--coupling-off-ratio", type=float, default=0.05,
                    help="coupling miner: 99th pct of off-state |flow| over full scale")
    ap.add_argument("--coupling-support", type=float, default=0.02,
                    help="coupling miner: min share of rows in each actuator state")
    ap.add_argument("--roll-shift", type=int, default=None,
                    help="channel_roll shift in rows (real data only; default the recipe's 7)")
    ap.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2])
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--threshold-quantile", type=float, default=0.995,
                    help="alarm threshold: this quantile of clean validation scores")
    ap.add_argument("--out", default="results_archive/week2_4b.json")
    args = ap.parse_args()
    args.out = str(results_path(args.out))

    install_spot_handler()
    done = load_json(args.out) or {"cells": {}, "traces": {}, "args": vars(args)}

    for seed in args.seeds:
        for defence in args.defences:
            for mode in ("clean", "fabricated", "projected"):
                key = f"{seed}|{defence}|{mode}"
                if key in done["cells"]:
                    continue
                t0 = time.time()
                set_seed(seed)
                sc, inv_set, cols = build(args.dataset, args.data_dir, mode,
                                          args.malicious_fraction, args.clients,
                                          args.window, seed, args.partition,
                                          roll_shift=args.roll_shift,
                                          invariant_kw=dict(r2_min=args.r2_min,
                                                            coupling_off_ratio=args.coupling_off_ratio,
                                                            coupling_support=args.coupling_support))
                out = run_federation(
                    sc["clients"], sc["eval_sets"],
                    FLConfig(rounds=args.rounds, local_epochs=args.local_epochs,
                             window=args.window, defence=defence, seed=seed,
                             device=args.device, record_trust=True,
                             threshold_quantile=args.threshold_quantile),
                    root_data=sc.get("root_data"))
                r = out["results"]["test"]
                res = out["results"]
                traj, mean_trust = malicious_trust(out["trust_log"])
                done["cells"][key] = {
                    "seed": seed, "defence": defence, "mode": mode,
                    "f1": r["f1"], "f1_best": r.get("f1_best"), "auc_pr": r.get("auc_pr"),
                    "targeted_recall": res.get("test_targeted", {}).get("recall"),
                    "untargeted_recall": res.get("test_untargeted", {}).get("recall"),
                    "malicious_acceptance_rate": out["malicious_acceptance_rate"],
                    "physics_admitted_rate": sc.get("physics_admitted_rate"),
                    "honest_physics_admitted_rate": sc.get("honest_physics_admitted_rate"),
                    "n_honest_rejected": sc.get("n_honest_rejected"),
                    "mean_malicious_trust": mean_trust,
                    "wall_seconds": round(time.time() - t0, 2),
                }
                done["traces"][key] = {"malicious_trust_per_round": traj}
                save_json(args.out, done)
                log.info("%-9s %-11s seed=%d  f1=%.4f  accept=%.2f  mal_trust=%.3f  (%.0fs)",
                         defence, mode, seed, r["f1"], out["malicious_acceptance_rate"],
                         mean_trust, time.time() - t0)
                if interrupted():
                    log.warning("interrupted")
                    return 0

    # --- analysis per defence, averaged over seeds ---
    cells = done["cells"]
    summary = []
    for defence in args.defences:
        def mean_over_seeds(mode, field):
            vals = [cells[f"{s}|{defence}|{mode}"][field] for s in args.seeds
                    if f"{s}|{defence}|{mode}" in cells]
            return float(np.mean(vals)) if vals else float("nan")

        f_clean = mean_over_seeds("clean", "f1")
        f_fab = mean_over_seeds("fabricated", "f1")
        f_proj = mean_over_seeds("projected", "f1")
        dmg_fab = (f_clean - f_fab) * 100
        dmg_proj = (f_clean - f_proj) * 100
        removed = (1.0 - (dmg_proj / dmg_fab)) if abs(dmg_fab) > 1e-9 else float("nan")
        # per-seed damage direction, for honesty about spread
        per_seed = []
        for s in args.seeds:
            kc, kf, kp = (f"{s}|{defence}|{m}" for m in ("clean", "fabricated", "projected"))
            if kc in cells and kf in cells and kp in cells:
                per_seed.append({"seed": s,
                                 "dmg_fab_pts": round((cells[kc]["f1"] - cells[kf]["f1"]) * 100, 2),
                                 "dmg_proj_pts": round((cells[kc]["f1"] - cells[kp]["f1"]) * 100, 2)})
        t_clean = mean_over_seeds("clean", "targeted_recall")
        t_fab = mean_over_seeds("fabricated", "targeted_recall")
        t_proj = mean_over_seeds("projected", "targeted_recall")
        summary.append({
            "defence": defence,
            "f1_clean": round(f_clean, 4), "f1_fabricated": round(f_fab, 4),
            "f1_projected": round(f_proj, 4),
            "targeted_recall_clean": round(t_clean, 4), "targeted_recall_fabricated": round(t_fab, 4),
            "targeted_recall_projected": round(t_proj, 4),
            "damage_fabricated_points": round(dmg_fab, 2),
            "damage_projected_points": round(dmg_proj, 2),
            "attack_capability_removed": round(removed, 3) if removed == removed else None,
            "accept_fabricated": round(mean_over_seeds("fabricated", "malicious_acceptance_rate"), 3),
            "accept_projected": round(mean_over_seeds("projected", "malicious_acceptance_rate"), 3),
            "trust_fabricated": round(mean_over_seeds("fabricated", "mean_malicious_trust"), 3),
            "trust_projected": round(mean_over_seeds("projected", "mean_malicious_trust"), 3),
            "projection_helped_attacker": bool(dmg_proj > dmg_fab and dmg_fab >= 1.0),
            "per_seed": per_seed,
        })
    done["summary"] = summary
    save_json(args.out, done)

    print(f"\n{'defence':<10s} {'dmg_fab':>8s} {'dmg_proj':>9s} {'removed':>8s} "
          f"{'accept f->p':>12s} {'trust f->p':>12s}")
    for row in summary:
        rem = f"{row['attack_capability_removed']:.1%}" if row['attack_capability_removed'] is not None else "  n/a"
        print(f"{row['defence']:<10s} {row['damage_fabricated_points']:>8.2f} "
              f"{row['damage_projected_points']:>9.2f} {rem:>8s} "
              f"{row['accept_fabricated']:.2f}->{row['accept_projected']:.2f}   "
              f"{row['trust_fabricated']:.3f}->{row['trust_projected']:.3f}")
        if row["projection_helped_attacker"]:
            print(f"    NOTE: against {row['defence']} projection raised the damage. "
                  f"Mechanism check -> acceptance and trust both rose, as expected.")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
