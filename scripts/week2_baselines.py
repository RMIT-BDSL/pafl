#!/usr/bin/env python3
"""Week 2. Train the baselines on real data, under every attack.

This is the main sweep the week-2 plan calls for, in one resumable driver. It
answers, for each defence and each attack, two questions: did the aggregation
rule accept the malicious contribution, and how far did the shared detector's F1
fall. The clean (attack-free) run of each defence is the reference every drop is
measured against.

Attacks come in two families and the driver handles both:

* Data fabrications -- channel_roll, and the other Recipe A transforms, and
  recipe_b -- poison the training data. The physics admission check is designed
  for these.
* Update-space attacks -- sign_flip, scaling, additive_noise, free_rider, alie,
  min_max -- poison the submitted update directly. The existing robust rules are
  designed for several of these. Running both families in one table is how the
  paper shows the two defence ideas are complementary.

Datasets:
    --dataset swat --data-dir <folder holding SWaT>   real SWaT
    --dataset batadal --data-dir <folder>             real BATADAL
    --dataset synthetic                               the simulator (no data needed)

Resumable: every (seed, defence, attack, malicious-fraction) cell is written to
the results file the moment it finishes, so a Colab session cutoff or an AWS
spot reclamation costs at most one cell.
"""
from __future__ import annotations
import argparse
import itertools
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.fl.defences import DEFENCES
from pafl.fl.train import FLConfig, run_federation
from pafl.attacks.recipe_a import FABRICATIONS
from pafl.attacks.update_attacks import UPDATE_ATTACKS
from pafl.eval.metrics import attack_success
from pafl.data.real import load_real
from pafl.utils.ckpt import install_spot_handler, interrupted, load_json, save_json
from pafl.utils.paths import results_path
from pafl.utils.logging import get_logger
from pafl.utils.seeds import set_seed

log = get_logger("week2")

DATA_FABRICATIONS = set(FABRICATIONS) | {"recipe_b"}


def build_scenario(dataset: str, data_dir: str | None, attack: str, mal: float,
                   clients: int, window: int, seed: int, partition: str,
                   roll_shift: int | None = None, invariant_kw: dict | None = None):
    """Return a federation dict for the requested dataset and attack."""
    is_update = attack in UPDATE_ATTACKS
    fabrication = "channel_roll" if is_update else attack   # placeholder unused when update attack
    update_attack = attack if is_update else None

    if dataset == "synthetic":
        from pafl.fl.scenario import ScenarioConfig, build_synthetic_scenario
        cfg = ScenarioConfig(n_clients=clients, malicious_fraction=mal,
                             fabrication=fabrication, window=window, seed=seed,
                             update_attack=update_attack)
        return build_synthetic_scenario(cfg)

    # real data
    from pafl.fl.scenario_real import RealScenarioConfig, build_real_scenario
    normal, attack_df = load_real(dataset, data_dir)
    cfg = RealScenarioConfig(n_clients=clients, malicious_fraction=mal,
                             fabrication=fabrication, roll_shift=roll_shift, window=window,
                             seed=seed, partition=partition, update_attack=update_attack,
                             **(invariant_kw or {}))
    return build_real_scenario(normal, attack_df, cfg)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="synthetic", choices=["synthetic", "swat", "wadi", "batadal"])
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--defences", nargs="+", default=list(DEFENCES))
    ap.add_argument("--attacks", nargs="+",
                    default=["channel_roll", "recipe_b", "sign_flip", "scaling",
                             "free_rider", "min_max"])
    ap.add_argument("--malicious-fractions", nargs="+", type=float, default=[0.0, 0.3])
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=30)
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
    ap.add_argument("--out", default="results/week2_baselines.json")
    args = ap.parse_args()
    args.out = str(results_path(args.out))

    install_spot_handler()
    inv_kw = dict(r2_min=args.r2_min, coupling_off_ratio=args.coupling_off_ratio,
                  coupling_support=args.coupling_support)
    done = load_json(args.out) or {"cells": {}, "args": vars(args)}

    # clean cells are attack-independent: run once per (seed, defence) at mal=0
    plan = []
    for seed, defence in itertools.product(args.seeds, args.defences):
        plan.append((seed, defence, "clean", 0.0))
        for attack in args.attacks:
            for mal in args.malicious_fractions:
                if mal == 0.0:
                    continue
                plan.append((seed, defence, attack, mal))

    log.info("%d cells (%d already done)", len(plan), len(done["cells"]))

    for seed, defence, attack, mal in plan:
        key = f"{seed}|{defence}|{attack}|{mal}"
        if key in done["cells"]:
            continue
        t0 = time.time()
        set_seed(seed)
        sc = build_scenario(args.dataset, args.data_dir, attack, mal,
                            args.clients, args.window, seed, args.partition,
                            roll_shift=args.roll_shift, invariant_kw=inv_kw)
        out = run_federation(
            sc["clients"], sc["eval_sets"],
            FLConfig(rounds=args.rounds, local_epochs=args.local_epochs,
                     window=args.window, defence=defence, seed=seed,
                     device=args.device, record_trust=True,
                     threshold_quantile=args.threshold_quantile),
            root_data=sc.get("root_data"))
        r = out["results"]["test"]
        res = out["results"]
        done["cells"][key] = {
            "seed": seed, "defence": defence, "attack": attack, "malicious_fraction": mal,
            "f1": r["f1"], "recall": r["recall"], "precision": r["precision"],
            "auc_pr": r.get("auc_pr"), "f1_best": r.get("f1_best"),
            "targeted_recall": res.get("test_targeted", {}).get("recall"),
            "untargeted_recall": res.get("test_untargeted", {}).get("recall"),
            "malicious_acceptance_rate": out["malicious_acceptance_rate"],
            "physics_admitted_rate": sc.get("physics_admitted_rate"),
            "wall_seconds": round(time.time() - t0, 2),
        }
        save_json(args.out, done)
        pa = sc.get("physics_admitted_rate")
        log.info("%-11s %-14s mal=%.2f seed=%d  f1=%.4f  accept=%.2f  physics_admit=%s  (%.0fs)",
                 defence, attack, mal, seed, r["f1"], out["malicious_acceptance_rate"],
                 f"{pa:.2f}" if pa is not None else "n/a", time.time() - t0)
        if interrupted():
            log.warning("interrupted; %d cells done", len(done["cells"]))
            return 0

    # --- summarise: F1 drop of each attack against each defence, vs its clean cell ---
    cells = done["cells"]
    summary = []
    for seed, defence in itertools.product(args.seeds, args.defences):
        clean = cells.get(f"{seed}|{defence}|clean|0.0")
        if not clean:
            continue
        for attack in args.attacks:
            for mal in args.malicious_fractions:
                if mal == 0.0:
                    continue
                cell = cells.get(f"{seed}|{defence}|{attack}|{mal}")
                if not cell:
                    continue
                a = attack_success(clean["f1"], cell["f1"])
                tr_c, tr_a = clean.get("targeted_recall"), cell.get("targeted_recall")
                summary.append({"seed": seed, "defence": defence, "attack": attack,
                                "malicious_fraction": mal,
                                "f1_clean": clean["f1"], "f1_attacked": cell["f1"],
                                "f1_drop_points": round(a["f1_drop_absolute"] * 100, 2),
                                "f1_best_clean": clean.get("f1_best"), "f1_best_attacked": cell.get("f1_best"),
                                "targeted_recall_clean": tr_c, "targeted_recall_attacked": tr_a,
                                "targeted_recall_drop_points":
                                    round((tr_c - tr_a) * 100, 2) if tr_c is not None and tr_a is not None else None,
                                "untargeted_recall_clean": clean.get("untargeted_recall"),
                                "untargeted_recall_attacked": cell.get("untargeted_recall"),
                                "physics_admitted_rate": cell.get("physics_admitted_rate"),
                                "malicious_acceptance_rate": cell["malicious_acceptance_rate"]})
    done["summary"] = summary
    save_json(args.out, done)

    print(f"\n{'defence':<12s} {'attack':<14s} {'mal':>4s} {'drop pts':>9s} {'tgt-rec drop':>12s} {'accept':>7s}")
    for row in summary:
        td = row["targeted_recall_drop_points"]
        print(f"{row['defence']:<12s} {row['attack']:<14s} {row['malicious_fraction']:>4.2f} "
              f"{row['f1_drop_points']:>9.2f} {(f'{td:.2f}' if td is not None else 'n/a'):>12s} "
              f"{row['malicious_acceptance_rate']:>7.2f}")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
