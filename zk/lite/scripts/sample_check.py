#!/usr/bin/env python3
"""Sampling soundness and budget sizing from the exported batches, without proofs.

Two questions the circuit's budgets raise, answered on the integer model's own
per-row counts (the same quantities the circuit sums):

  * honest false rejection: draw k distinct indices from 1..N-1 of an honest
    N-row window, sum the per-row violation and inapplicability counts, repeat;
    report P(v <= v_max) and P(u <= u_max) for candidate budgets;
  * detection: for each attack batch, P(v > v_max) over the same draws, next to
    the exact hypergeometric value for v_max = 0 (no violating row among k of
    the V violating rows) and the (1 - rho)^k approximation the plan quotes.

    python3 scripts/sample_check.py data/batches_swat_wide_seed0.json --draws 20000
"""
from __future__ import annotations
import argparse
import json
from math import comb
from pathlib import Path

import numpy as np

LITE = Path(__file__).resolve().parents[1]


def draw_sums(v_rows: np.ndarray, u_rows: np.ndarray, k: int, draws: int, rs: np.random.Generator):
    """Sum v and u over k distinct indices of one window (rows 1..N-1), `draws` times."""
    n = len(v_rows)
    idx = np.argsort(rs.random((draws, n)), axis=1)[:, :k]      # k distinct positions per draw
    return v_rows[idx].sum(axis=1), u_rows[idx].sum(axis=1)


def honest_windows(pool: dict, N: int) -> list[tuple[np.ndarray, np.ndarray]]:
    """Every full N-row window (stride N/2) of every honest shard."""
    v_all, u_all = np.array(pool["violations"]), np.array(pool["inapplicable"])
    out, off = [], 0
    for span in pool["rows_per_client"]:
        v, u = v_all[off:off + span], u_all[off:off + span]
        off += span
        for s in range(0, span - (N - 1) + 1, N // 2):
            out.append((v[s:s + N - 1], u[s:s + N - 1]))
    return out


def exact_no_violation(n_rows: int, n_viol: int, k: int) -> float:
    """P(no violating row among k drawn without replacement) = C(n-V, k) / C(n, k)."""
    if n_viol > n_rows - k:
        return 0.0
    return comb(n_rows - n_viol, k) / comb(n_rows, k)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("batches", nargs="?", default=str(LITE / "data" / "batches_swat_wide_seed0.json"))
    ap.add_argument("--draws", type=int, default=20000)
    ap.add_argument("--ks", default="8,16,32,64")
    ap.add_argument("--vmaxes", default="0,1,2,3")
    ap.add_argument("--umaxes", default="0,2,4,6,8,12,16,24")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=str(LITE / "results_sampling.json"))
    a = ap.parse_args()
    d = json.load(open(a.batches))
    N = d["N"]
    ks = [int(x) for x in a.ks.split(",")]
    vmaxes = [int(x) for x in a.vmaxes.split(",")]
    umaxes = [int(x) for x in a.umaxes.split(",")]
    rs = np.random.default_rng(a.seed)

    # ---- honest budgets, over every honest window of the federation's honest shards
    wins = honest_windows(d["honest_pool_row_stats"], N)
    per_win = max(1, a.draws // len(wins))
    honest = {}
    for k in ks:
        vs, us = [], []
        for v_rows, u_rows in wins:
            v, u = draw_sums(v_rows, u_rows, k, per_win, rs)
            vs.append(v); us.append(u)
        vs, us = np.concatenate(vs), np.concatenate(us)
        honest[k] = {
            "draws": int(len(vs)), "windows": len(wins),
            "v_mean": float(vs.mean()), "u_mean": float(us.mean()),
            "P_v_le": {str(m): float((vs <= m).mean()) for m in vmaxes},
            "P_u_le": {str(m): float((us <= m).mean()) for m in umaxes},
            "v_quantiles": {q: int(np.quantile(vs, float(q))) for q in ("0.9", "0.99", "0.999", "1.0")},
            "u_quantiles": {q: int(np.quantile(us, float(q))) for q in ("0.9", "0.99", "0.999", "1.0")},
        }

    # ---- detection on the exported batches
    detect = {}
    for name, b in d["batches"].items():
        v_rows, u_rows = np.array(b["row_violations"]), np.array(b["row_inapplicable"])
        n_viol = int((v_rows > 0).sum())
        rho = n_viol / len(v_rows)
        per_k = {}
        for k in ks:
            v, u = draw_sums(v_rows, u_rows, k, a.draws, rs)
            per_k[k] = {
                "P_reject_v_gt": {str(m): float((v > m).mean()) for m in vmaxes},
                "P_reject_u_gt": {str(m): float((u > m).mean()) for m in umaxes},
                "exact_P_detect_vmax0": 1.0 - exact_no_violation(len(v_rows), n_viol, k),
                "approx_1_minus_1_minus_rho_k": 1.0 - (1.0 - rho) ** k,
                "v_mean": float(v.mean()), "u_mean": float(u.mean()),
            }
        detect[name] = {"violating_rows": n_viol, "rows": int(len(v_rows)), "rho": rho,
                        "rows_with_inapplicable": int((u_rows > 0).sum()), "per_k": per_k}

    out = {"batches_file": a.batches, "N": N, "draws": a.draws, "honest_budgets": honest, "detection": detect}
    json.dump(out, open(a.out, "w"), indent=1)

    print(f"honest windows: {len(wins)} of {N} rows over {len(d['honest_pool_row_stats']['clients'])} shards; "
          f"violating row rate {d['honest_pool_row_stats']['violating_row_fraction']:.4f}")
    print(f"{'k':>3} {'E[v]':>6} {'E[u]':>6} | " + " ".join(f"P(v<={m}):{'':>3}" for m in vmaxes) + " | " + " ".join(f"P(u<={m})" for m in umaxes))
    for k in ks:
        h = honest[k]
        print(f"{k:>3} {h['v_mean']:6.3f} {h['u_mean']:6.3f} | " + " ".join(f"{h['P_v_le'][str(m)]:10.4f}" for m in vmaxes)
              + " | " + " ".join(f"{h['P_u_le'][str(m)]:9.4f}" for m in umaxes))
    print()
    print(f"{'batch':13s} {'rho':>7} | " + " ".join(f"k={k:<3}" for k in ks) + "   P(reject) with v_max = 1;  exact P(detect) at v_max = 0 in brackets")
    for name, r in detect.items():
        cells = " ".join(f"{r['per_k'][k]['P_reject_v_gt']['1']:.3f}[{r['per_k'][k]['exact_P_detect_vmax0']:.3f}]" for k in ks)
        print(f"{name:13s} {r['rho']:7.4f} | {cells}")
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
