#!/usr/bin/env python3
"""The adaptive attacker: what does the physics check cost a poisoner who knows it is there?

This is the driver behind the paper's main results (the `*_adaptive_*` files). For
each seed and aggregation rule it runs the same federation in up to five modes
(pafl.fl.variants.MODES; paper names in brackets):

  clean        all clients honest                                    [clean]
  honest_only  the attacked run's honest clients alone, no attacker  [honest-only]
  fabricated   malicious clients train on poisoned data, no check    [naive attack]
  projected    they first project that data onto the invariants, so
               the check admits more of it; every update is kept     [physics-aware attack]
  gated        projected, and the server excludes any client whose
               batch still fails the check                           [gated]

`--fabrication` picks the poison. `splice_only` replays real attack rows as normal
(the paper's replay); `channel_roll` shifts actuator channels against the sensors
(`--roll-shift 60` rows = 5 min at SWaT's 5 s stride is the paper's setting). Each
cell stores global F1, AUC-PR and recall on the targeted attacks (the labelled
attacks the malicious clients try to hide) and on the other attacks. It also stores
both "doors": the share of malicious updates the rule accepted, and the share of
malicious batches the check admitted. In the physics-aware and gated modes,
`projection` records what the projection cost the attacker, in standard deviations
of shift per malicious batch.

The paper's numbers come from the cells, not from the summary this script prints.
The paper measures damage on targeted-attack recall against the honest_only run of
the same seed. It pools only seeds where the naive attack cost at least one point,
weighted by that damage. `scripts/summarize_adaptive.py <file>` prints exactly those
numbers. The summary at the end of this script is the pilot's "criterion 4", kept for
continuity and stored in the file as `summary`, `headline_attack_capability_removed`
and `criterion_4_pass`. It uses a different reference (the clean run), pools seeds
before differencing, scores F1, and keeps rules with at least 3 points of damage.

Several defaults are not the paper's settings: --dataset synthetic, four rules,
--malicious-fraction 0.2, and a roll shift of 7. The paper's commands, one per
committed file, are in scripts/reproduce.sh; for example

    python scripts/adaptive.py --dataset swat --r2-min 0.40 --coupling-off-ratio 0.10 \
        --coupling-support 0.005 --defences fedavg krum median trimmed_mean norm_clip fltrust \
        foolsgold --fabrication splice_only --malicious-fraction 0.3 --clients 10 --rounds 25 \
        --local-epochs 2 --seeds 0 1 2 3 4 --out results/swat_adaptive_wide_splice_5seed.json

Resumable: each (seed, rule, mode) cell is written to --out as soon as it finishes,
and a rerun with the same --out skips the cells already there. Every cell reseeds
and rebuilds its federation from scratch, so cells do not depend on run order. A
file filled in stages equals one run of the final command, provided the code did
not change between stages. Two consequences for a replicator:
- a stale file at --out silently short-circuits the run;
- the file's `args` block records only the invocation that created the file. Several
  committed files were extended later (more seeds, rules or modes), so read the seeds,
  rules and modes from the cell keys, not from `args`.
"""
from __future__ import annotations
import argparse
import json
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

log = get_logger("adaptive")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="synthetic", choices=["synthetic", "swat", "wadi", "batadal"])
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--partition", default="temporal", choices=["temporal", "iid"])
    ap.add_argument("--defences", nargs="+", default=["fedavg", "krum", "trimmed_mean", "fltrust"])
    ap.add_argument("--fabrication", default="channel_roll")
    ap.add_argument("--modes", nargs="+",
                    default=["clean", "honest_only", "fabricated", "projected", "gated"],
                    help="clean (10 honest) | honest_only (the 7 honest shards of the attacked run) | "
                         "fabricated | projected (all clients stay in) | gated (rejected batches "
                         "excluded: the deployed system)")
    ap.add_argument("--r2-min", type=float, default=0.60, help="balance R^2 cut for the miner (real data)")
    ap.add_argument("--coupling-off-ratio", type=float, default=0.05,
                    help="coupling miner: 99th pct of off-state |flow| over full scale")
    ap.add_argument("--coupling-support", type=float, default=0.02,
                    help="coupling miner: min share of rows in each actuator state")
    ap.add_argument("--target-attack-fraction", type=float, default=None,
                    help="share of a malicious shard replaced by attack segments (default 0.25). "
                         "Lower it on records whose attacks all fit the budget, so an untargeted set exists")
    ap.add_argument("--roll-shift", type=int, default=None,
                    help="channel_roll shift in rows (real data only; default the recipe's 7)")
    ap.add_argument("--malicious-fraction", type=float, default=0.2)
    ap.add_argument("--clients", type=int, default=10)
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--local-epochs", type=int, default=2)
    ap.add_argument("--steps-per-client", type=int, default=4000)   # simulated plant only
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--seeds", nargs="+", type=int, default=[0])
    # store_true with default=True: always on, and the flag cannot switch it off.
    # Every committed run projected with actuator states protected.
    ap.add_argument("--protect-status", action="store_true", default=True,
                    help="the attacker will not write fractional actuator states")
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--threshold-quantile", type=float, default=0.995,
                    help="alarm threshold: this quantile of clean validation scores")
    ap.add_argument("--out", default="results_archive/adaptive.json")
    args = ap.parse_args()
    args.out = str(results_path(args.out))

    install_spot_handler()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    done = load_json(args.out) or {"cells": {}, "projection": [], "args": vars(args)}

    for seed in args.seeds:
        for defence in args.defences:
            for mode in args.modes:
                key = f"{seed}|{defence}|{mode}"
                if key in done["cells"]:
                    continue
                set_seed(seed)          # per cell, so a cell is the same whatever ran before it
                t0 = time.time()
                stats: list = []        # filled by the projection (projected and gated modes)
                sc, inv_set, cols = build_variant(
                    args.dataset, mode, args.malicious_fraction, args.clients, args.window,
                    seed, data_dir=args.data_dir, partition=args.partition,
                    fabrication=args.fabrication, roll_shift=args.roll_shift,
                    target_attack_fraction=args.target_attack_fraction,
                    invariant_kw=dict(r2_min=args.r2_min, coupling_off_ratio=args.coupling_off_ratio,
                                      coupling_support=args.coupling_support),
                    steps_per_client=args.steps_per_client,
                    protect_status=args.protect_status, proj_stats=stats)
                out = run_federation(
                    sc["clients"], sc["eval_sets"],
                    FLConfig(rounds=args.rounds, local_epochs=args.local_epochs,
                             window=args.window, defence=defence, seed=seed,
                             device=args.device, log_every=10_000, record_trust=True,
                             threshold_quantile=args.threshold_quantile),
                    root_data=sc.get("root_data"))
                r = out["results"]["test"]
                res = out["results"]
                done["cells"][key] = {
                    "seed": seed, "defence": defence, "mode": mode,
                    "f1": r["f1"], "recall": r["recall"], "precision": r["precision"],
                    "auc_pr": r.get("auc_pr"), "f1_best": r.get("f1_best"),
                    "targeted_recall": res.get("test_targeted", {}).get("recall"),
                    "untargeted_recall": res.get("test_untargeted", {}).get("recall"),
                    "malicious_acceptance_rate": out["malicious_acceptance_rate"],
                    "physics_admitted_rate": sc.get("physics_admitted_rate"),
                    "n_excluded_by_gate": sc.get("n_excluded_by_gate"),
                    "n_malicious_excluded_by_gate": sc.get("n_malicious_excluded_by_gate"),
                    "n_honest_excluded_by_gate": sc.get("n_honest_excluded_by_gate"),
                    "honest_physics_admitted_rate": sc.get("honest_physics_admitted_rate"),
                    "n_honest_rejected": sc.get("n_honest_rejected"),
                    "n_malicious_in_round": sc.get("n_malicious"),
                    "n_invariants": len(inv_set),
                    "wall_seconds": round(time.time() - t0, 2),
                }
                done["projection"].extend(stats)
                save_json(args.out, done)
                log.info("%-12s %-11s seed=%d  f1=%.4f  mal_accept=%.2f  (%.0fs)",
                         defence, mode, seed, r["f1"], out["malicious_acceptance_rate"],
                         time.time() - t0)
                if interrupted():
                    log.warning("interrupted")
                    return 0

    # ---- pilot summary (criterion 4); see the module docstring for how it differs
    # ---- from the paper's removal numbers (scripts/summarize_adaptive.py)
    cells = list(done["cells"].values())
    summary = []
    for d in args.defences:
        g = {m: [c["f1"] for c in cells if c["defence"] == d and c["mode"] == m]
             for m in ("clean", "fabricated", "projected")}
        if not all(g.values()):
            continue
        f_clean, f_fab, f_proj = (float(np.mean(g[m])) for m in ("clean", "fabricated", "projected"))
        dmg_fab = f_clean - f_fab
        dmg_proj = f_clean - f_proj
        removed = 1.0 - (dmg_proj / dmg_fab) if dmg_fab > 1e-9 else float("nan")
        row = {
            "defence": d, "f1_clean": f_clean, "f1_fabricated": f_fab, "f1_projected": f_proj,
            "damage_fabricated_points": dmg_fab * 100,
            "damage_projected_points": dmg_proj * 100,
            "attack_capability_removed": removed,
        }
        # the same three numbers on the targeted attacks' recall, when the
        # scenario defines a target set (real data)
        tg = {m: [c["targeted_recall"] for c in cells
                  if c["defence"] == d and c["mode"] == m and c.get("targeted_recall") is not None]
              for m in ("clean", "fabricated", "projected")}
        if all(tg.values()):
            t_clean, t_fab, t_proj = (float(np.mean(tg[m])) for m in ("clean", "fabricated", "projected"))
            td_fab, td_proj = t_clean - t_fab, t_clean - t_proj
            row.update({
                "targeted_recall_clean": t_clean, "targeted_recall_fabricated": t_fab,
                "targeted_recall_projected": t_proj,
                "targeted_damage_fabricated_points": td_fab * 100,
                "targeted_damage_projected_points": td_proj * 100,
                "attack_capability_removed_targeted":
                    1.0 - (td_proj / td_fab) if td_fab > 1e-9 else float("nan"),
            })
        summary.append(row)
    done["summary"] = summary
    removed_all = [s["attack_capability_removed"] for s in summary
                   if np.isfinite(s["attack_capability_removed"])]
    done["mean_attack_capability_removed"] = float(np.mean(removed_all)) if removed_all else float("nan")

    # Criterion 4 is scored on the defence the attack actually damaged, for the
    # same reason criterion 3 uses the best drop rather than the mean. Averaging
    # over aggregation rules that rejected the malicious client outright divides
    # by a damage of roughly zero, and a rule the attack never hurt tells you
    # nothing about whether the invariant requirement weakens the attacker.
    scored = [s for s in summary if s["damage_fabricated_points"] >= 3.0]
    done["scored_defences"] = [s["defence"] for s in scored]
    done["headline_attack_capability_removed"] = (
        float(np.mean([s["attack_capability_removed"] for s in scored])) if scored else float("nan"))
    done["criterion_4_pass"] = bool(
        scored and np.mean([s["attack_capability_removed"] for s in scored]) >= 0.5)
    # An attack made WORSE by the projection is a finding, not a rounding error.
    done["projection_helped_attacker"] = [
        s["defence"] for s in summary if s["attack_capability_removed"] < 0
        and s["damage_fabricated_points"] >= 1.0]
    save_json(args.out, done)

    print("\n{:<14s} {:>9s} {:>11s} {:>11s} {:>12s}".format(
        "defence", "f1 clean", "f1 fabric.", "f1 project.", "removed"))
    for s in summary:
        print("{:<14s} {:>9.4f} {:>11.4f} {:>11.4f} {:>11.1f}%".format(
            s["defence"], s["f1_clean"], s["f1_fabricated"], s["f1_projected"],
            100 * s["attack_capability_removed"]))
        if "targeted_recall_clean" in s:
            print("   targeted recall {:>7.4f} {:>11.4f} {:>11.4f} {:>11.1f}%".format(
                s["targeted_recall_clean"], s["targeted_recall_fabricated"],
                s["targeted_recall_projected"], 100 * s["attack_capability_removed_targeted"]))
    if done["projection"]:
        shifts = [p["mean_abs_shift_sigma"] for p in done["projection"]]
        print(f"\nprojection cost: {np.mean(shifts):.4f} sigma mean shift "
              f"across {len(shifts)} malicious batches")
    scored = done.get("scored_defences", [])
    print(f"\nscored on defences the attack actually damaged: {scored or 'none'}")
    print(f"attack capability removed there: {done['headline_attack_capability_removed']:.1%}")
    print(f"(unweighted mean across all defences: {done['mean_attack_capability_removed']:.1%})")
    if done.get("projection_helped_attacker"):
        print("\nWARNING: the projection made the attack STRONGER against "
              f"{', '.join(done['projection_helped_attacker'])}."
              "\nThat is a finding, not noise to average away. Re-run with more seeds"
              "\nbefore trusting it, then investigate: moving a fabricated batch onto"
              "\nthe physics manifold also moves its update toward the honest cone,"
              "\nwhich raises its similarity score and therefore its trust weight.")
    print("CRITERION 4 (adaptive attacker weakened):",
          "PASS" if done["criterion_4_pass"] else "FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
