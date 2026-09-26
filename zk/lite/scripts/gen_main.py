#!/usr/bin/env python3
"""Write the circom main for one invariant set and one sample count.

Reads a fixed-point invariant export (zk/data/invariants_*.json), lays the
invariant channels out in the order the leaf hash uses, bakes every coefficient,
constant and tolerance into the template parameters and writes

    build/<tag>/main.circom       the component main
    build/<tag>/circuit_meta.json what the input builder needs: channel layout,
                                  chunking, depth, k, K, bit widths, budgets

Nothing here reads telemetry, so the circuit, its constraint count and its keys
can be built from the committed invariant files alone. run_bench.sh calls this
when build/<tag>/main.circom is absent; by hand, from zk/lite:

    python3 scripts/gen_main.py --invariants ../data/invariants_swat_wide.json --k 32
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LITE = HERE.parent
DEFAULT_INV = LITE.parent / "data" / "invariants_swat_wide.json"          # zk/data/


def chunking(n: int) -> tuple[int, int]:
    """(chunks, chunk size): the fewest chunks of at most 16 inputs (circomlib's Poseidon
    limit), equal in size. Must match chunkCount/chunkSize in the circuit and
    chunkedHashPlus in build_inputs.mjs."""
    nc = (n + 15) // 16
    cs = (n + nc - 1) // nc
    return nc, cs


def fmt_list(xs) -> str:
    return "[" + ", ".join(str(int(x)) for x in xs) + "]"


def fmt_matrix(rows) -> str:
    return "[\n    " + ",\n    ".join(fmt_list(r) for r in rows) + "\n  ]"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--invariants", default=str(DEFAULT_INV))
    ap.add_argument("--k", type=int, default=32)
    ap.add_argument("--depth", type=int, default=10, help="Merkle depth; N = 2^depth rows")
    # 32 bits: SWaT's largest |x_hat| is ~6.65e7 < 2^26 (LIT301 ~ 1014 mm), so the
    # 2^31 bias leaves wide headroom for readings the projection pushes negative
    ap.add_argument("--x-bits", type=int, default=32, help="range check on every opened channel value")
    ap.add_argument("--tag", default=None, help="build subdirectory; default <setting>_k<k>")
    a = ap.parse_args()

    q = json.load(open(a.invariants))
    S = q["S"]
    setting = q["provenance"]["setting"]
    tag = a.tag or f"{setting}_k{a.k}"
    out_dir = LITE / "build" / tag
    out_dir.mkdir(parents=True, exist_ok=True)

    inv_channels = list(q["channels_touched"])          # leaf order = export order (column order)
    n_inv = len(inv_channels)
    pos = {ch: i for i, ch in enumerate(inv_channels)}
    rest_channels = [c for c in q["columns"] if c not in pos]

    rules = q["invariants"]
    n_rules = len(rules)
    coef_prev = [[0] * n_inv for _ in rules]
    coef_cur = [[0] * n_inv for _ in rules]
    c_hat, eps_hat, is_coupling, status_idx, off_hat, on_hat = [], [], [], [], [], []
    for j, inv in enumerate(rules):
        for ch, v in inv["coef_prev"].items():
            coef_prev[j][pos[ch]] = int(v["int"])
        for ch, v in inv["coef_cur"].items():
            coef_cur[j][pos[ch]] = int(v["int"])
        c_hat.append(int(inv["c_hat"]))
        eps_hat.append(int(inv["eps_hat"]))
        app = inv["applicability"]
        if app["type"] == "coupling":
            is_coupling.append(1)
            status_idx.append(pos[app["status_channel"]])
            # SWaT actuator states are small integers, so these are exact multiples of S
            off_hat.append(int(round(app["off_value"] * S)))
            on_hat.append(int(round(app["on_value"] * S)))
            assert off_hat[-1] != on_hat[-1]
        else:
            # balances always apply; the zeros are placeholders the circuit never reads
            is_coupling.append(0)
            status_idx.append(0)
            off_hat.append(0)
            on_hat.append(0)

    # Channel values enter the circuit biased, x_enc = x_hat + B with B = 2^(xBits-1), so a
    # signed reading (the projection can push a near-zero flow below zero) is still an
    # unsigned xBits-bit integer.  The bias is absorbed into the constants:
    #   r = sum coef (x_enc - B) + c = sum coef x_enc + (c - B sum coef)
    B = 1 << (a.x_bits - 1)
    c_circ = [c_hat[j] - B * (sum(coef_prev[j]) + sum(coef_cur[j])) for j in range(n_rules)]
    off_circ = [v + B if is_coupling[j] else 0 for j, v in enumerate(off_hat)]
    on_circ = [v + B if is_coupling[j] else 0 for j, v in enumerate(on_hat)]

    # residual bound: |r| <= sum |coef| (2^xBits - 1) + |c'|; the soft range check needs |r| < K.
    # K is the next power of two above 2 r_bound, a factor of two of slack; for the wide set
    # r_bound < 2^53, K = 2^54 and rBits = 56, far below the ~254-bit field
    x_max = (1 << a.x_bits) - 1
    r_bound = max(sum(abs(v) for v in coef_prev[j] + coef_cur[j]) * x_max + abs(c_circ[j]) for j in range(n_rules))
    K = 1 << (r_bound.bit_length() + 1)                 # K > 2 |r|max
    r_bits = (K + max(eps_hat) + 1).bit_length() + 1    # LessEqThan operands must be < 2^rBits
    assert r_bits <= 250

    params = [
        str(a.k), str(a.depth), str(n_inv), str(n_rules), str(a.x_bits), str(r_bits), str(K),
        fmt_matrix(coef_prev), fmt_matrix(coef_cur), fmt_list(c_circ), fmt_list(eps_hat),
        fmt_list(is_coupling), fmt_list(status_idx), fmt_list(off_circ), fmt_list(on_circ),
    ]
    src = f"""pragma circom 2.1.9;
// generated by scripts/gen_main.py from {Path(a.invariants).name}
// setting {setting}: {n_rules} rules over {n_inv} of {len(q['columns'])} channels; k = {a.k}; N = 2^{a.depth}
include "../../circuits/invariant_check.circom";

component main {{public [root, idx, vMax, uMax]}} = InvariantCheck(
  {", ".join(params[:7])},
  {params[7]},
  {params[8]},
  {params[9]},
  {params[10]},
  {params[11]},
  {params[12]},
  {params[13]},
  {params[14]}
);
"""
    (out_dir / "main.circom").write_text(src)

    nc, cs = chunking(n_inv)
    ncr, csr = chunking(len(rest_channels))
    meta = {
        "tag": tag, "setting": setting, "invariants_file": str(Path(a.invariants).resolve()),
        "k": a.k, "depth": a.depth, "N": 1 << a.depth,
        "S": S, "x_bits": a.x_bits, "x_bias": B, "r_bits": r_bits, "K": str(K), "r_bound": str(r_bound),
        "encoding": "every channel value enters the circuit (hash preimage and arithmetic) as x_hat + x_bias; "
                    "the constants below are the raw ones, the circuit's are shifted accordingly",
        "columns": q["columns"],
        "inv_channels": inv_channels, "rest_channels": rest_channels,
        "leaf": {"inv_chunks": nc, "inv_chunk_size": cs,
                 "rest_chunks": ncr, "rest_chunk_size": csr,
                 "rule": "h_rest = Poseidon(chunk digests of rest channels, 0); "
                         "leaf = Poseidon(chunk digests of inv channels, h_rest); "
                         "chunks are equal-sized (<= 16), zero padded"},
        "rules": [{"name": inv["name"], "is_coupling": is_coupling[j], "status_idx": status_idx[j],
                   "off_hat": off_hat[j], "on_hat": on_hat[j], "eps_hat": eps_hat[j], "c_hat": c_hat[j],
                   "coef_prev": coef_prev[j], "coef_cur": coef_cur[j]} for j, inv in enumerate(rules)],
        "public_inputs": ["root", "idx[k]", "vMax", "uMax"],
        "sampling": "idx_m = Poseidon(root, nonce, ctr) mod (N-1) + 1, distinct, derived by the verifier",
    }
    json.dump(meta, open(out_dir / "circuit_meta.json", "w"), indent=1)
    print(f"wrote {out_dir.relative_to(LITE)}/main.circom  ({setting}: {n_rules} rules, {n_inv} channels, k={a.k}, "
          f"K=2^{K.bit_length()-1}, rBits={r_bits}, leaf chunks {nc}x{cs})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
