"""Where the data and the results live.

One rule, so that the same command works on a laptop, on Colab with Google
Drive mounted, and on an AWS instance, without editing any script.

The project root is the directory that holds this package. Data goes in
`<root>/data` and results go in `<root>/results`. Two environment variables
override those defaults, which is what the Colab notebook sets so the results
land on Drive and survive a disconnected runtime:

    PAFL_DATA_DIR
    PAFL_RESULTS_DIR

Dataset folder names are matched without regard to case, because the published
archives use upper case (BATADAL, HAI) and the scripts refer to them in lower
case.
"""
from __future__ import annotations
import os
from pathlib import Path

# .../<root>/pafl/utils/paths.py  ->  <root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def project_root() -> Path:
    return PROJECT_ROOT


def results_dir() -> Path:
    """Directory for result files. Created if it does not exist."""
    d = Path(os.environ.get("PAFL_RESULTS_DIR") or (PROJECT_ROOT / "results"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def results_path(name: str) -> Path:
    """Resolve one result file.

    An absolute path, or any path that already names a directory, is returned
    unchanged. A bare file name is placed in the results directory. This lets
    `--out results/day1.json` and `--out day1.json` and an absolute Drive path
    all behave the way the caller expects.
    """
    p = Path(name)
    if p.is_absolute():
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    if p.parent != Path("."):
        # caller gave an explicit relative directory: honour it as written
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    return results_dir() / p.name


def data_root() -> Path:
    """Directory that holds the dataset folders."""
    env = os.environ.get("PAFL_DATA_DIR")
    if env:
        return Path(env)
    here = PROJECT_ROOT / "data"
    if here.exists():
        return here
    # a checkout kept beside a shared data folder, as on this laptop
    beside = PROJECT_ROOT.parent / "data"
    return beside if beside.exists() else here


def dataset_dir(name: str) -> Path:
    """Find one dataset folder, ignoring the case of its name.

    Raises FileNotFoundError with the directories that were searched, because
    a wrong data path is the most common reason a run fails on a new machine.
    """
    root = data_root()
    exact = root / name
    if exact.exists():
        return exact
    if root.exists():
        want = name.lower()
        for child in root.iterdir():
            if child.is_dir() and child.name.lower() == want:
                return child
    raise FileNotFoundError(
        f"dataset folder {name!r} not found under {root}. "
        f"Set PAFL_DATA_DIR to the folder that holds it, or pass --data-dir."
    )


def find_csv(directory: Path, *stems: str) -> Path:
    """First CSV in `directory` whose name contains one of `stems`.

    Matching ignores case. The stems are tried in order, so the caller states
    its preference once instead of writing the same loop in every script.
    """
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(f"no such directory: {directory}")
    csvs = sorted(directory.glob("*.csv"))
    if not csvs:
        raise FileNotFoundError(f"no CSV files in {directory}")
    for stem in stems:
        s = stem.lower()
        for c in csvs:
            if s in c.name.lower():
                return c
    return csvs[0]
