#!/usr/bin/env python3
"""Render results.json (+ results_sampling.json) as Markdown and LaTeX for the paper's ZK subsection.

Prints the cost table, the three-proof demonstration and the sampling table in
README.md; the 40-round table there comes from nonce_sweep.sh instead. "MB" is
2^20 bytes throughout (as is the MB in the peak-RSS figures), and the proof size is
that of snarkjs's JSON file. From zk/lite:

    python3 scripts/make_table.py wide_k32 [wide_k16 ...] > build/table.md
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

LITE = Path(__file__).resolve().parents[1]


def fmt_s(x):
    return "–" if x is None else (f"{x:.2f} s" if x < 10 else f"{x:.0f} s" if x < 600 else f"{x / 60:.1f} min")


def fmt_b(x):
    return "–" if x is None else (f"{x / 2**20:.1f} MB" if x >= 2**20 else f"{x / 1024:.1f} kB" if x >= 1024 else f"{x} B")


def main(tags: list[str]) -> int:
    res = json.load(open(LITE / "results.json"))
    samp = json.load(open(LITE / "results_sampling.json")) if (LITE / "results_sampling.json").exists() else None
    rows = [res[t] for t in tags]

    print("## Circuit and prover cost (Groth16, snarkjs, " + (rows[0]["machine"] or "") + ")\n")
    hdr = ["", *[f"k = {r['k']}" for r in rows]]
    lines = [
        ["R1CS constraints", *[f"{r['constraints']:,}" for r in rows]],
        ["constraints per sample", *[f"{r['constraints_per_sample']:,}" for r in rows]],
        ["public / private inputs", *[f"{r['public_inputs']} / {r['private_inputs']:,}" for r in rows]],
        ["compile", *[fmt_s(r["compile_seconds"]) for r in rows]],
        ["setup (peak RSS)", *[f"{fmt_s(r['setup_seconds'])} ({r['setup_max_rss_mb']} MB)" if r["setup_seconds"] else "–" for r in rows]],
        ["proving key", *[fmt_b(r["zkey_bytes"]) for r in rows]],
        ["verification key", *[fmt_b(r["vk_bytes"]) for r in rows]],
    ]
    hb = rows[0]["batches"].get("honest", {})
    for name in ("honest", "projected"):
        for r in rows:
            b = r["batches"].get(name)
            if b and b.get("witness_generated"):
                lines.append([f"witness, {name} batch", *[fmt_s(rr["batches"].get(name, {}).get("witness_seconds")) for rr in rows]])
                lines.append([f"prove, {name} batch (peak RSS)", *[f"{fmt_s(rr['batches'].get(name, {}).get('prove_seconds'))} ({rr['batches'].get(name, {}).get('prove_max_rss_mb')} MB)" for rr in rows]])
                lines.append([f"verify, {name} batch", *[fmt_s(rr["batches"].get(name, {}).get("verify_seconds")) for rr in rows]])
                lines.append(["proof size", *[fmt_b(rr["batches"].get(name, {}).get("proof_bytes")) for rr in rows]])
                break
        else:
            continue
        break
    print("| " + " | ".join(hdr) + " |")
    print("|" + "---|" * len(hdr))
    for l in lines:
        print("| " + " | ".join(l) + " |")

    print("\n## The three-proof demonstration (vMax = %s, uMax = %s)\n" % (hb.get("v_max"), hb.get("u_max")))
    print("| batch | violating rows in batch | violations / inapplicable in the k samples | outcome |")
    print("|---|---|---|---|")
    for r in rows:
        for name, b in r["batches"].items():
            fv = b.get("float_verdict") or {}
            outcome = ("proof verifies" if b.get("verified") else "proof FAILS verification") if b.get("witness_generated") \
                else "witness generation aborts (budget exceeded)"
            print(f"| {name} (k = {r['k']}) | {fv.get('violating_fraction', float('nan')):.2%} | "
                  f"{b['violations_in_samples']} / {b['inapplicable_in_samples']} | {outcome} |")

    if samp:
        print("\n## Sampling: honest false-rejection and detection (integer model, %d draws)\n" % samp["draws"])
        ks = sorted(int(k) for k in samp["honest_budgets"])
        print("| k | E[v] honest | P(v ≤ 1) | P(v ≤ 2) | P(u ≤ 8) | P(reject roll, vMax 1) | P(reject splice) | P(reject projected) |")
        print("|---|---|---|---|---|---|---|---|")
        for k in ks:
            h = samp["honest_budgets"][str(k)]
            d = samp["detection"]
            g = lambda n: d[n]["per_k"][str(k)]["P_reject_v_gt"]["1"]
            print(f"| {k} | {h['v_mean']:.3f} | {h['P_v_le']['1']:.4f} | {h['P_v_le']['2']:.4f} | {h['P_u_le']['8']:.4f} | "
                  f"{g('channel_roll'):.3f} | {g('splice_only'):.3f} | {g('projected'):.3f} |")

    # LaTeX
    print("\n%% LaTeX\n\\begin{tabular}{l" + "r" * len(rows) + "}\n\\toprule")
    print(" & ".join(hdr) + " \\\\\n\\midrule")
    for l in lines:
        print(" & ".join(x.replace("%", "\\%") for x in l) + " \\\\")
    print("\\bottomrule\n\\end{tabular}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or ["wide_k32"]))
