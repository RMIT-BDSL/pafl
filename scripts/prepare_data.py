#!/usr/bin/env python3
"""Fetch and verify the real datasets.

Only public sources are downloaded. SWaT and WADI are request-based, so this
script expects you to place the files yourself and then verifies them; it never
tries to fetch them, and it never uploads them anywhere. The iTrust licence
forbids redistribution, so if you stage them in S3, make sure the bucket blocks
public access at the account level first.
"""
from __future__ import annotations
import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pafl.utils.logging import get_logger      # noqa: E402

log = get_logger("data")

SOURCES = {
    "hai": {
        "kind": "git",
        "url": "https://github.com/icsdataset/hai",
        "note": "CC BY-SA 4.0. Process and endpoint telemetry only, no packet captures. "
                "Needs git-lfs: run `git lfs install` first.",
    },
    "batadal": {
        "kind": "manual",
        "url": "https://www.batadal.net/data.html",
        "note": "Training dataset 1 and 2 plus the test dataset. Small CSVs. "
                "Mirrors exist if the original host is down.",
    },
    "icsnad": {
        "kind": "manual",
        "url": "https://doi.org/10.57760/sciencedb.25938",
        "note": "246 GB across 272 files. Take the CSV feature files first; the PCAPs "
                "are only needed for protocol-level work. Science Data Bank, open access.",
    },
    "swat": {
        "kind": "manual",
        "url": "https://itrust.sutd.edu.sg/itrust-labs_datasets/",
        "note": "iTrust OneDrive. Use SWaT.A1 & A2_Dec 2015: the canonical split with a "
                "Normal file (~7 days) and an Attack file (36 labelled attacks). The .zip is "
                "~101 GB because it bundles the network captures; take the process-data .xlsx "
                "files only (a few hundred MB). Loader: pafl.data.swat. No redistribution.",
    },
    "wadi": {
        "kind": "manual",
        "url": "https://itrust.sutd.edu.sg/itrust-labs_datasets/",
        "note": "iTrust OneDrive. WADI.A1_9 Oct 2017 (848 MB) and WADI.A2_19 Nov 2019 (575 MB). "
                "Second real distribution network, optional secondary dataset. No redistribution.",
    },
}


def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while blk := f.read(chunk):
            h.update(blk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", choices=sorted(SOURCES) + ["all"], default="all")
    ap.add_argument("--root", default="data")
    ap.add_argument("--manifest", default="data/MANIFEST.txt")
    args = ap.parse_args()

    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    names = sorted(SOURCES) if args.dataset == "all" else [args.dataset]

    for name in names:
        spec = SOURCES[name]
        dest = root / name
        if spec["kind"] == "git":
            if dest.exists():
                log.info("%s already present at %s", name, dest)
            elif shutil.which("git") is None:
                log.error("git not found; clone %s manually into %s", spec["url"], dest)
            else:
                log.info("cloning %s", spec["url"])
                subprocess.run(["git", "clone", "--depth", "1", spec["url"], str(dest)], check=False)
                subprocess.run(["git", "-C", str(dest), "lfs", "pull"], check=False)
        else:
            dest.mkdir(parents=True, exist_ok=True)
            log.info("%s: place the files in %s yourself", name, dest)
            log.info("        source: %s", spec["url"])
            log.info("        note:   %s", spec["note"])

    lines = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.parts and p.name != Path(args.manifest).name:
            lines.append(f"{sha256(p)}  {p.relative_to(root)}  {p.stat().st_size}")
    Path(args.manifest).write_text("\n".join(lines) + "\n")
    log.info("manifest written: %s (%d files)", args.manifest, len(lines))
    log.info("commit the manifest. It is what makes the run reproducible, and it is "
             "what you cite when a reviewer asks which version of SWaT you used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
