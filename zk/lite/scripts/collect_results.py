#!/usr/bin/env python3
"""Fold one build's measurements into results.json (keyed by tag).

run_bench.sh calls this as its last step; it reads only build/<tag>/ (steps.jsonl,
compile.log, r1cs_info.txt, the .expect.json side files, proofs and keys), so it can
be rerun without repeating the benchmark. Times are wall seconds of each CLI process
and memory is peak RSS in MiB, both from /usr/bin/time as run_bench.sh records them (-l
on macOS, a GNU -f format on Linux); the toolchain and machine fields are read from the
host at collection time, not at measurement time.

    python3 scripts/collect_results.py wide_k32
"""
from __future__ import annotations
import datetime as dt
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

LITE = Path(__file__).resolve().parents[1]


def main(tag: str) -> int:
    b = LITE / "build" / tag
    meta = json.load(open(b / "circuit_meta.json"))
    steps = [json.loads(l) for l in open(b / "steps.jsonl") if l.strip()]
    by = {s["step"]: s for s in steps}
    ptau = by.get("ptau", {}).get("path")
    info = (b / "r1cs_info.txt").read_text() if (b / "r1cs_info.txt").exists() else ""
    grab = lambda label: int(m.group(1)) if (m := re.search(rf"{label}:\s*(\d+)", info)) else None
    compile_log = (b / "compile.log").read_text() if (b / "compile.log").exists() else ""
    nl = re.search(r"non-linear constraints:\s*(\d+)", compile_log)
    # (?<!non-): "linear constraints" also occurs inside "non-linear constraints", so an
    # unanchored pattern read the non-linear count twice (the values committed before 26 Sep 2026)
    li = re.search(r"(?<!non-)linear constraints:\s*(\d+)", compile_log)

    def size(p):
        p = b / p
        return p.stat().st_size if p.exists() else None

    batches = {}
    for name in ("honest", "channel_roll", "projected", "splice_only"):
        exp = b / f"input_{name}.expect.json"
        if not exp.exists():
            continue
        e = json.load(open(exp))
        w = by.get(f"witness_{name}")
        verified = None
        vlog = b / f"verify_{name}.log"
        if vlog.exists():
            verified = "OK!" in vlog.read_text()
        batches[name] = {
            "client": e.get("client"), "start": e.get("start"), "nonce": e["nonce"], "idx": e["idx"],
            "violations_in_samples": e["violations"], "inapplicable_in_samples": e["inapplicable"],
            "v_max": e["vMax"], "u_max": e["uMax"], "within_budget": e["within_budget"],
            "float_verdict": e.get("float_verdict"), "integer_verdict": e.get("integer_verdict"),
            "js_python_cross_check": e.get("python_cross_check"),
            "witness_generated": (w is not None and w["exit"] == 0),
            "witness_seconds": w["seconds"] if w else None,
            "prove_seconds": by.get(f"prove_{name}", {}).get("seconds"),
            "prove_max_rss_mb": round(by[f"prove_{name}"]["max_rss_bytes"] / 2**20) if f"prove_{name}" in by else None,
            "verify_seconds": by.get(f"verify_{name}", {}).get("seconds"),
            "verified": verified,
            "proof_bytes": size(f"proof_{name}.json"),     # snarkjs's JSON (decimal coordinates), not binary
            "public_inputs": len(json.load(open(b / f"public_{name}.json"))) if (b / f"public_{name}.json").exists() else None,
        }

    def ver(cmd):
        # first non-empty output line, whatever the exit status: `snarkjs --version` prints
        # "snarkjs@0.7.4" and then its usage text, and exits 99
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        lines = [l.strip() for l in (r.stdout + r.stderr).splitlines() if l.strip()]
        return lines[0] if lines else None

    def cpu_name():
        if platform.system() == "Darwin":
            return ver(["sysctl", "-n", "machdep.cpu.brand_string"])
        try:
            for line in open("/proc/cpuinfo"):
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            pass
        return platform.processor() or platform.machine() or None

    entry = {
        "tag": tag, "setting": meta["setting"], "k": meta["k"], "depth": meta["depth"], "N": meta["N"],
        "n_rules": len(meta["rules"]), "n_inv_channels": len(meta["inv_channels"]), "x_bits": meta["x_bits"],
        "r_bits": meta["r_bits"], "constraints": grab("# of Constraints"),
        "constraints_nonlinear": int(nl.group(1)) if nl else None, "constraints_linear": int(li.group(1)) if li else None,
        "constraints_per_sample": round(grab("# of Constraints") / meta["k"]) if grab("# of Constraints") else None,
        "wires": grab("# of Wires"), "public_inputs": grab("# of Public Inputs"), "private_inputs": grab("# of Private Inputs"),
        "compile_seconds": by.get("compile", {}).get("seconds"),
        "setup_seconds": by.get("setup", {}).get("seconds"),
        "setup_max_rss_mb": round(by["setup"]["max_rss_bytes"] / 2**20) if "setup" in by else None,
        "zkey_bytes": size("circuit.zkey"), "vk_bytes": size("vk.json"), "wasm_bytes": size("main_js/main.wasm"),
        "r1cs_bytes": size("main.r1cs"), "ptau": Path(ptau).name if ptau else None,   # file name only, no local path
        "batches": batches,
        "toolchain": {"circom": ver(["circom", "--version"]), "snarkjs": ver(["snarkjs", "--version"]),
                      "node": ver(["node", "--version"])},
        "machine": cpu_name(),
        "measured": dt.datetime.now().isoformat(timespec="seconds"),
    }
    out = LITE / "results.json"
    res = json.load(open(out)) if out.exists() else {}
    res[tag] = entry
    json.dump(res, open(out, "w"), indent=1)
    c = entry["constraints"]
    print(f"results.json[{tag}]: {c} constraints ({entry['constraints_per_sample']}/sample), "
          f"setup {entry['setup_seconds']} s, " +
          ", ".join(f"{n}: {'proof ' + ('OK' if v['verified'] else 'FAIL') if v['witness_generated'] else 'witness aborted'}"
                    f"{' (' + str(v['prove_seconds']) + ' s)' if v['prove_seconds'] else ''}" for n, v in batches.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
