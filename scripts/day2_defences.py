#!/usr/bin/env python3
"""Day 2. Do the baseline defences accept the fabricated updates?

For each defence we run the federation twice: once with every client honest, and
once with a fraction of clients training on a fabricated batch. Two numbers come
out. How often the aggregation rule accepted the malicious update, and how far
the shared detector's F1 fell.

The paper needs the answer to be "accepted, and it fell". If the baselines
already catch this, there is no gap and Idea 1 is the fallback.

Resumable: every cell is written to the results file as it finishes, so a Colab
session ending at twelve hours or an AWS spot reclamation costs one cell.
"""
from __future__ import annotations
import argparse
import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.fl.defences import DEFENCES
from pafl.fl.scenario import ScenarioConfig, build_synthetic_scenario
from pafl.fl.train import FLConfig, run_federation
from pafl.eval.metrics import attack_success
from pafl.utils.ckpt import install_spot_handler, interrupted, load_json, save_json
from pafl.utils.paths import results_path
from pafl.utils.logging import get_logger
from pafl.utils.seeds import set_seed

log = get_logger("day2")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--defences", nargs="+", default=list(DEFENCES))
    ap.add_argument("--fabrication", default="channel_roll")
    ap.add_argument("--malicious-fractions", nargs="+", type=float, default=[0.0, 0.2])
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--local-epochs", type=int, default=2)
    ap.add_argument("--steps-per-client", type=int, default=5000)
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--seeds", nargs="+", type=int, default=[0])
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--out", default="results_archive/day2_defences.json")
    args = ap.parse_args()
    args.out = str(results_path(args.out))

    install_spot_handler()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    done = load_json(args.out) or {"cells": {}, "args": vars(args)}

    grid = list(itertools.product(args.seeds, args.defences, args.malicious_fractions))
    log.info("%d cells (%d already done)", len(grid), len(done["cells"]))

    for seed, defence, mal in grid:
        key = f"{seed}|{defence}|{mal}"
        if key in done["cells"]:
            continue
        t0 = time.time()
        set_seed(seed)
        sc = build_synthetic_scenario(ScenarioConfig(
            n_clients=args.clients, malicious_fraction=mal, fabrication=args.fabrication,
            steps_per_client=args.steps_per_client, window=args.window, seed=seed))
        out = run_federation(
            sc["clients"], sc["eval_sets"],
            FLConfig(rounds=args.rounds, local_epochs=args.local_epochs, window=args.window,
                     defence=defence, seed=seed, device=args.device, log_every=10_000),
            root_data=sc["root_data"])
        r = out["results"]["test"]
        done["cells"][key] = {
            "seed": seed, "defence": defence, "malicious_fraction": mal,
            "n_malicious": out["n_malicious"],
            "f1": r["f1"], "precision": r["precision"], "recall": r["recall"],
            "auc_pr": r["auc_pr"], "fpr": r["false_positive_rate"],
            "attacks_detected": r["attacks_detected"], "attacks_missed": r["attacks_missed"],
            "malicious_acceptance_rate": out["malicious_acceptance_rate"],
            "wall_seconds": out["wall_seconds"],
        }
        save_json(args.out, done)
        log.info("%-12s mal=%.2f seed=%d  f1=%.4f  mal_accept=%.2f  (%.0fs)",
                 defence, mal, seed, r["f1"], out["malicious_acceptance_rate"],
                 time.time() - t0)
        if interrupted():
            log.warning("interrupted; %d cells complete", len(done["cells"]))
            return 0

    # ---- summarise: F1 drop per defence, averaged over seeds ----
    cells = list(done["cells"].values())
    base_frac = min(args.malicious_fractions)
    atk_frac = max(args.malicious_fractions)
    summary = []
    for d in args.defences:
        clean = [c["f1"] for c in cells if c["defence"] == d and c["malicious_fraction"] == base_frac]
        pois = [c["f1"] for c in cells if c["defence"] == d and c["malicious_fraction"] == atk_frac]
        acc = [c["malicious_acceptance_rate"] for c in cells
               if c["defence"] == d and c["malicious_fraction"] == atk_frac]
        if not clean or not pois:
            continue
        a = attack_success(float(np.mean(clean)), float(np.mean(pois)))
        summary.append({
            "defence": d,
            "f1_clean": float(np.mean(clean)),
            "f1_poisoned": float(np.mean(pois)),
            "f1_drop_points": a["f1_drop_absolute"] * 100,
            "malicious_acceptance_rate": float(np.mean(acc)),
            "accepted": bool(np.mean(acc) > 0.5),
        })
    done["summary"] = summary
    n_accepting = sum(s["accepted"] for s in summary)
    drops = [s["f1_drop_points"] for s in summary] or [0.0]
    mean_drop, best_drop = float(np.mean(drops)), float(np.max(drops))
    # Criteria 2 and 3 are separate questions and are scored separately, the same
    # way go_nogo.py does it. Criterion 3 uses the BEST drop, not the mean: an
    # attack that defeats one deployed aggregation rule is a real threat even if
    # the other five absorb it, and averaging over rules that reject the client
    # outright would hide exactly the case the paper is about.
    done["criterion_2_pass"] = bool(n_accepting >= 3)
    done["criterion_3_pass"] = bool(best_drop >= 3.0)
    done["best_drop_points"] = best_drop
    done["mean_drop_points"] = mean_drop
    save_json(args.out, done)

    print("\n{:<14s} {:>9s} {:>10s} {:>10s} {:>9s}".format(
        "defence", "f1 clean", "f1 pois.", "drop (pts)", "accepted"))
    for s in summary:
        print("{:<14s} {:>9.4f} {:>10.4f} {:>10.2f} {:>9.2f}".format(
            s["defence"], s["f1_clean"], s["f1_poisoned"], s["f1_drop_points"],
            s["malicious_acceptance_rate"]))
    print(f"\ndefences accepting the malicious update: {n_accepting}/{len(summary)}")
    print(f"F1 drop: best {best_drop:.2f} points, mean {mean_drop:.2f} points")
    print("CRITERION 2 (baselines accept the update):",
          "PASS" if done["criterion_2_pass"] else "FAIL")
    print("CRITERION 3 (detection actually falls):",
          "PASS" if done["criterion_3_pass"] else "FAIL")
    if best_drop >= 3.0 and mean_drop < 3.0:
        print("\nNote: the damage is concentrated in one aggregation rule. Report which,"
              "\nand do not claim the fabrication defeats robust aggregation in general.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
