#!/usr/bin/env python3
"""Compare a rerun result file with the committed one, number by number.

    python scripts/compare_results.py results/swat_adaptive_wide_splice_5seed.json \
        results_archive/reproduce/swat_adaptive_wide_splice_5seed.json

Walks both JSON files and reports every number that differs by more than --tol,
every string that differs, and every key or cell present in only one file. Exit
status 0 means the rerun reproduced the committed file within the tolerance.

Some fields are expected to differ and are skipped:
  wall_seconds, seconds   timing
  args                    the committed file records only the invocation that
                          created it (several were extended later; see adaptive.py)
The `projection` list of an adaptive file is compared as a multiset, because a
file filled in stages appends its entries in a different order from a single run.

Every cell reseeds before it runs, so a rerun with the same code on the same
machine should match exactly. Across machines, BLAS and PyTorch builds can move the
last digits of a float and, rarely, flip an alarm at the threshold, so start with
--tol 1e-6 and look at what exceeds it.
"""
from __future__ import annotations
import argparse
import json
import math

SKIP = {"wall_seconds", "seconds", "args"}


def _projection_key(p: dict) -> tuple:
    return tuple(sorted((k, round(v, 9) if isinstance(v, float) else v)
                        for k, v in p.items() if k not in SKIP))


def diff(a, b, path: str, tol: float, out: list) -> None:
    """Append one line to `out` for every difference between `a` and `b` under `path`."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k in SKIP:
                continue
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'committed' if k in a else 'rerun'}")
            elif k == "projection" and isinstance(a[k], list):
                if sorted(map(_projection_key, a[k])) != sorted(map(_projection_key, b[k])):
                    out.append(f"{path}/{k}: projection records differ ({len(a[k])} vs {len(b[k])})")
            else:
                diff(a[k], b[k], f"{path}/{k}", tol, out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path}: length {len(a)} vs {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diff(x, y, f"{path}[{i}]", tol, out)
    elif isinstance(a, bool) or isinstance(b, bool) or not isinstance(a, (int, float)) \
            or not isinstance(b, (int, float)):
        if a != b and not (a is None and b is None):
            out.append(f"{path}: {a!r} vs {b!r}")
    else:
        if math.isnan(a) and math.isnan(b):
            return
        if not math.isclose(a, b, rel_tol=0.0, abs_tol=tol):
            out.append(f"{path}: {a!r} vs {b!r} (diff {abs(a - b):.3g})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("committed")
    ap.add_argument("rerun")
    ap.add_argument("--tol", type=float, default=1e-9, help="absolute tolerance on every number")
    ap.add_argument("--max-lines", type=int, default=40)
    a = ap.parse_args()
    with open(a.committed) as f:
        ca = json.load(f)
    with open(a.rerun) as f:
        cb = json.load(f)
    out: list[str] = []
    diff(ca, cb, "", a.tol, out)
    if not out:
        print(f"identical within {a.tol:g}: {a.rerun}")
        return 0
    print(f"{len(out)} differences (tolerance {a.tol:g}):")
    for line in out[:a.max_lines]:
        print("  " + line)
    if len(out) > a.max_lines:
        print(f"  ... {len(out) - a.max_lines} more")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
