#!/usr/bin/env python3
"""Day 1. The cheapest kill criterion, and it needs no federated learning.

Question: do the invariant residuals of honest data and fabricated data
separate? If the two distributions overlap, the premise of the paper fails here,
for the price of an afternoon, and you switch to Idea 1 with four days lost
instead of four weeks.

Outputs results_archive/day1_residuals.json and a histogram by default; the paper's criterion-1 runs pass
--out results/c1_<dataset>_<set>_<shift>.json. The PNG always goes to results_archive/ (plots are not committed).
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.data.loaders import feature_columns
from pafl.data.synthetic import simulate, default_attacks
from pafl.attacks.recipe_a import FABRICATIONS, fabricate
from pafl.invariants.mine import build_invariant_set
from pafl.invariants.plants import synthetic_invariants
import pandas as pd
from pafl.utils.paths import dataset_dir, results_path
from pafl.utils.logging import get_logger
from pafl.utils.seeds import set_seed

log = get_logger("day1")


def overlap_coefficient(a: np.ndarray, b: np.ndarray, bins: int = 200) -> float:
    """Fraction of probability mass the two distributions share.

    Zero means perfectly separated, one means identical. The go criterion asks
    for less than 0.05.
    """
    lo = float(min(a.min(), b.min()))
    hi = float(max(a.max(), b.max()))
    if hi <= lo:
        return 1.0
    edges = np.linspace(lo, hi, bins + 1)
    pa, _ = np.histogram(a, bins=edges, density=False)
    pb, _ = np.histogram(b, bins=edges, density=False)
    pa = pa / max(pa.sum(), 1)
    pb = pb / max(pb.sum(), 1)
    return float(np.minimum(pa, pb).sum())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default="synthetic",
                    choices=["synthetic", "batadal", "swat", "wadi", "hai"],
                    help="dataset to evaluate")
    ap.add_argument("--r2-min", type=float, default=0.60, help="swat: balance R^2 cut for the miner")
    ap.add_argument("--coupling-off-ratio", type=float, default=0.05,
                    help="swat: coupling miner off-state bound (99th pct of |flow| / full scale)")
    ap.add_argument("--coupling-support", type=float, default=0.02,
                    help="swat: coupling miner minimum share of rows per actuator state")
    ap.add_argument("--roll-shift", type=int, default=None,
                    help="channel_roll shift in rows (default: the recipe's 7). SWaT at a "
                         "five-second stride needs a larger shift to match the pilot's "
                         "misalignment in plant time")
    ap.add_argument("--data-dir", default=None,
                    help="directory containing CSVs for batadal or hai")
    ap.add_argument("--hai-train-files", type=int, default=3,
                    help="how many HAI train CSVs to concatenate before mining")
    ap.add_argument("--hai-rows", type=int, default=0,
                    help="row budget for HAI; 0 uses max(3*steps, 30000). Rows are\n                         subsampled across the whole record, not taken from the front")
    ap.add_argument("--steps", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mined", action="store_true",
                    help="use automatically mined invariants instead of the ground-truth set")
    ap.add_argument("--n-batches", type=int, default=200,
                    help="how many batches to sample when testing separation")
    ap.add_argument("--batch-rows", type=int, default=1000,
                    help="rows in one client batch, i.e. what gets admitted or rejected")
    ap.add_argument("--max-violating-frac", type=float, default=0.01,
                    help="the admission rule: reject a batch above this violating fraction")
    ap.add_argument("--out", default="results_archive/day1_residuals.json")
    ap.add_argument("--figure", default=None,
                    help="histogram PNG; default results_archive/<stem of --out>.png")
    args = ap.parse_args()
    args.out = str(results_path(args.out))
    args.figure = str(results_path(args.figure or f"results_archive/{Path(args.out).stem}.png"))

    set_seed(args.seed)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    attack_rows_only = None
    roll_kw = {"shift": args.roll_shift} if args.roll_shift else {}

    def _fab(df, kind, seed):
        return fabricate(df, kind, seed=seed, **(roll_kw if kind == "channel_roll" else {}))

    if args.dataset == "synthetic":
        honest = simulate(args.steps, seed=args.seed)
        calib = simulate(args.steps, seed=args.seed + 5000)      # separate clean run for epsilon
        attacked = simulate(args.steps, seed=args.seed,
                            attacks=default_attacks(args.steps, seed=args.seed, n=8))
        if args.mined:
            inv, mining_report = build_invariant_set(calib, max_invariants=10)
            log.info("mined %d invariants from %d candidates",
                     len(inv), mining_report["candidates"]["total"])
        else:
            inv, mining_report = synthetic_invariants(calib, include_weak_bounds=False), None
    elif args.dataset == "batadal":
        # Use the dedicated loader and the data-fitted invariant set. The loader
        # repairs two file quirks that silently corrupt a run: the leading space
        # in every column name of the second file, and the -999 marker used for
        # unlabelled rows. The invariant set is FITTED to the clean half of the
        # record rather than hand-coded, so a wrong assumed tank area cannot bias
        # the result -- an earlier revision called the hand-coded set in
        # pafl/invariants/plants.py, whose assumed areas do not match this
        # network, and every fabrication was then admitted at a violating
        # fraction of 0.0000.
        from pafl.data.batadal import load_batadal, batadal_invariants as fit_batadal
        data_path = Path(args.data_dir) if args.data_dir else dataset_dir("batadal")
        full = load_batadal(data_path / "BATADAL_dataset03.csv")
        full = full.drop(columns=[c for c in ("datetime", "ATT_FLAG") if c in full.columns])
        n_half = len(full) // 2
        calib = full.iloc[:n_half].reset_index(drop=True)
        honest = full.iloc[n_half:].reset_index(drop=True)

        csv_test = data_path / "BATADAL_dataset04.csv"
        if csv_test.exists():
            attacked = load_batadal(csv_test)
            attacked = attacked.drop(columns=[c for c in ("datetime", "ATT_FLAG")
                                              if c in attacked.columns])
        else:
            attacked = honest

        if args.mined:
            inv, mining_report = build_invariant_set(calib, max_invariants=10)
            log.info("mined %d invariants from %d candidates",
                     len(inv), mining_report["candidates"]["total"])
        else:
            inv, mining_report = fit_batadal(calib)
            log.info("batadal invariants: %d kept (%d couplings, %d balances); dropped %d",
                     mining_report["kept_total"], mining_report["kept_couplings"],
                     mining_report["kept_balances"], len(mining_report["dropped_balances"]))
    elif args.dataset in ("swat", "wadi"):
        # Real SWaT or WADI, through the same loader, slicing and miner the federation
        # uses (pafl.fl.scenario_real), so the criterion-1 check here is the
        # check the federated runs enforce. Invariants are fitted on one clean
        # slice and calibrated on another; the rest of the normal record is the
        # honest pool the fabrications are applied to. --mined is implied: the
        # SWaT set is always the automatic one.
        from pafl.data.real import load_real
        from pafl.data.swat import swat_invariants
        normal, attack_df = load_real(args.dataset, args.data_dir)
        normal = normal.drop(columns=[c for c in normal.columns if "AIT" in str(c).upper()])
        attack_df = attack_df.drop(columns=[c for c in attack_df.columns if "AIT" in str(c).upper()])
        normal = normal.drop(columns=[c for c in ("datetime", "ATT_FLAG") if c in normal.columns])
        n_inv = int(len(normal) * 0.30)
        fit = normal.iloc[: n_inv // 2].reset_index(drop=True)
        calib = normal.iloc[n_inv // 2:n_inv].reset_index(drop=True)
        honest = normal.iloc[n_inv:].reset_index(drop=True)
        attacked = attack_df.drop(columns=[c for c in ("datetime",) if c in attack_df.columns])
        attack_rows_only = attacked[attacked["ATT_FLAG"] == 1].drop(columns=["ATT_FLAG"]) \
            .reset_index(drop=True)
        attacked = attacked.drop(columns=["ATT_FLAG"])
        inv, mining_report = swat_invariants(fit, r2_min=args.r2_min,
                                             coupling_off_ratio=args.coupling_off_ratio,
                                             coupling_support=args.coupling_support)
        log.info("%s invariants: %d kept (%d couplings, %d balances); dropped %d balances", args.dataset,
                 mining_report["kept_total"], mining_report["kept_couplings"],
                 mining_report["kept_balances"], len(mining_report["dropped_balances"]))
        for c in mining_report["couplings"]:
            log.info("  coupling %s -> %s  nominal %.3f  cv %.3f  off/on %g/%g",
                     c["status"], c["flow"], c["nominal"], c["cv"], c["off_value"], c["on_value"])
        for b in mining_report["balances"]:
            log.info("  balance  %s  r2 %.3f", b["tank"], b["r2"])
    elif args.dataset == "hai":
        data_path = Path(args.data_dir) if args.data_dir else dataset_dir("hai")
        csvs = sorted(p for p in data_path.glob("*.csv"))
        if not csvs:
            raise FileNotFoundError(f"no CSV files found in {data_path}")
        train_csvs = [p for p in csvs if "train" in p.name.lower()] or csvs
        test_csvs = [p for p in csvs if "test" in p.name.lower()]

        def _read_hai(path: Path) -> pd.DataFrame:
            """Read one HAI file and remove everything that is not a process channel.

            Two removals matter and neither is cosmetic.

            The label columns in HAI are lower case: `attack`, `attack_P1`,
            `attack_P2`, `attack_P3`. An earlier version of this branch dropped
            only `Attack` and `ATT_FLAG`, so all four labels were handed to the
            invariant miner as if they were sensors. Any rule mined from a label
            is a rule that reads the answer, so the match is made on the name in
            lower case and it covers every label column.

            Channels that never change carry no information. HAI holds 22 of
            them across the whole training set. They cannot enter a balance, and
            in the state-rule miner a constant actuator scores a perfect purity
            inside every operating state, which manufactures rules that say
            nothing. They are removed here rather than filtered later.
            """
            d = pd.read_csv(path)
            d.columns = d.columns.str.strip()
            drop = [c for c in d.columns
                    if c.lower() in ("time", "timestamp", "datetime")
                    or "attack" in c.lower()
                    or c.lower() in ("label", "att_flag")]
            d = d.drop(columns=drop)
            return d.select_dtypes(include=[np.number])

        df = pd.concat([_read_hai(p) for p in train_csvs[:args.hai_train_files]],
                       ignore_index=True)
        constant = [c for c in df.columns if df[c].nunique(dropna=True) <= 1]
        if constant:
            log.info("HAI: dropping %d channels that never change: %s",
                     len(constant), ", ".join(constant))
            df = df.drop(columns=constant)

        max_rows = args.hai_rows if args.hai_rows > 0 else max(args.steps * 3, 30000)
        if len(df) > max_rows:
            step = max(1, len(df) // max_rows)
            df = df.iloc[::step].head(max_rows).reset_index(drop=True)
            log.info("HAI: subsampled every %d-th row to %d rows spanning the whole record",
                     step, len(df))
        n_half = len(df) // 2
        calib = df.iloc[:n_half].reset_index(drop=True)
        honest = df.iloc[n_half:].reset_index(drop=True)

        if test_csvs:
            df_test = _read_hai(test_csvs[0])
            common_cols = [c for c in calib.columns if c in df_test.columns]
            if common_cols:
                calib = calib[common_cols]
                honest = honest[common_cols]
                attacked = df_test[common_cols]
            else:
                attacked = honest
        else:
            attacked = honest

        inv, mining_report = build_invariant_set(calib, max_invariants=10)
        log.info("mined %d invariants from %d candidates on HAI",
                 len(inv), mining_report["candidates"]["total"])

    cols = feature_columns(honest)
    inv.calibrate(calib)
    log.info("invariant set '%s' with %d rules", inv.name, len(inv))

    honest_verdict = inv.batch_verdict(honest)

    # The admission decision is taken on a batch, not on a row, so the statistic
    # that has to separate is the batch violating fraction. Row scores overlap
    # heavily even for a fabrication that is caught, because most rows of a
    # fabricated batch are still individually fine. Comparing row scores would
    # answer a question nobody asks.
    def batch_fractions(df, n_batches: int, batch_rows: int, rs) -> np.ndarray:
        out = []
        for _ in range(n_batches):
            i = int(rs.integers(1, max(2, len(df) - batch_rows)))
            out.append(inv.batch_verdict(df.iloc[i:i + batch_rows])["violating_fraction"])
        return np.asarray(out)

    rs = np.random.default_rng(args.seed + 999)
    honest_fracs = batch_fractions(honest, args.n_batches, args.batch_rows, rs)

    rows = []
    for kind in FABRICATIONS:
        if kind == "splice_only":          # the exposure-only control is not a fabrication of physics
            continue
        fab = _fab(honest, kind, args.seed + 11)
        fab_fracs = batch_fractions(fab, args.n_batches, args.batch_rows, rs)
        v = inv.batch_verdict(fab)
        ov = overlap_coefficient(honest_fracs, fab_fracs)
        admitted_rate = float(np.mean(fab_fracs <= args.max_violating_frac))
        rows.append({
            "fabrication": kind,
            "preserves": list(FABRICATIONS[kind].preserves),
            "violating_fraction_full": v["violating_fraction"],
            "batch_violating_mean": float(fab_fracs.mean()),
            "batch_violating_std": float(fab_fracs.std()),
            "batch_admitted_rate": admitted_rate,
            "overlap_with_honest": ov,
            "separated": ov < 0.05 and admitted_rate < 0.05,
        })
        log.info("%-26s batch_viol %.4f+-%.4f  admitted %.3f  overlap %.4f  %s",
                 kind, fab_fracs.mean(), fab_fracs.std(), admitted_rate, ov,
                 "SEPARATED" if rows[-1]["separated"] else "OVERLAPS")
    log.info("%-26s batch_viol %.4f+-%.4f  admitted %.3f (honest baseline)",
             "honest", honest_fracs.mean(), honest_fracs.std(),
             float(np.mean(honest_fracs <= args.max_violating_frac)))

    # A genuine attack on the plant, for reference: the invariants should also
    # flag real attacks, otherwise they are not measuring physics.
    #
    # Each dataset branch above already set `attacked` to its own labelled attack
    # record. Only the synthetic plant needs one generated here. An earlier
    # revision generated the simulated record unconditionally, which overwrote
    # the real one: the BATADAL run then crashed (the simulator has no S_PU7
    # channel) and the HAI run reported a reference that came from a different
    # plant altogether.
    if args.dataset == "synthetic":
        attacked = simulate(args.steps, seed=args.seed,
                            attacks=default_attacks(args.steps, seed=args.seed, n=8))
    missing = [c for c in attacked.columns if c not in honest.columns]
    if missing:
        log.warning("attack record has %d channels the clean record lacks: %s",
                    len(missing), ", ".join(missing[:6]))
    atk_verdict = inv.batch_verdict(attacked)
    atk_rows_verdict = inv.batch_verdict(attack_rows_only) if attack_rows_only is not None else None

    result = {
        "dataset": args.dataset,
        "steps": args.steps,
        "seed": args.seed,
        "invariant_set": inv.name,
        "n_invariants": len(inv),
        "invariants": [{"name": i.name, "kind": i.kind, "eps": i.eps, "note": i.note}
                       for i in inv],
        "circuit_cost_k64": inv.circuit_cost(64),
        "admission_rule": {"max_violating_frac": args.max_violating_frac,
                           "batch_rows": args.batch_rows, "n_batches": args.n_batches},
        "honest": honest_verdict,
        "honest_batch_violating_mean": float(honest_fracs.mean()),
        "honest_batch_false_reject_rate": float(np.mean(honest_fracs > args.max_violating_frac)),
        "real_attack_reference": atk_verdict,
        "real_attack_rows_only": atk_rows_verdict,
        "roll_shift": args.roll_shift,
        "fabrications": rows,
        "mining_report": mining_report,
        "criterion_1_pass": bool(
            sum(r["separated"] for r in rows) >= 2
            and float(np.mean(honest_fracs > args.max_violating_frac)) < 0.05),
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2, default=float)
    log.info("wrote %s", args.out)

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(7.8, 4.2), dpi=140)
        bins = np.linspace(0, 1.0, 60)
        ax.hist(honest_fracs, bins=bins, alpha=0.85, label="honest", color="#23508C")
        for r, kind in zip(rows, [k for k in FABRICATIONS if k != "splice_only"]):
            fab = _fab(honest, kind, args.seed + 11)
            ax.hist(batch_fractions(fab, args.n_batches, args.batch_rows,
                                    np.random.default_rng(args.seed + 999)),
                    bins=bins, histtype="step", linewidth=1.7,
                    label=f"{kind} (admitted {r['batch_admitted_rate']:.2f})")
        ax.axvline(args.max_violating_frac, color="#8C2A22", linestyle="--", linewidth=1.2,
                   label=f"admission threshold {args.max_violating_frac}")
        ax.set_yscale("log")
        ax.set_xlabel(f"violating fraction of a {args.batch_rows}-row client batch")
        ax.set_ylabel("batches (log)")
        ax.set_title("Day 1: do honest and fabricated batches separate?")
        ax.legend(fontsize=8)
        fig.tight_layout()
        fig.savefig(args.figure)
        log.info("wrote %s", args.figure)
    except Exception as e:
        log.warning("figure skipped: %s", e)

    print("\nCRITERION 1 (residual separation):",
          "PASS" if result["criterion_1_pass"] else "FAIL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
