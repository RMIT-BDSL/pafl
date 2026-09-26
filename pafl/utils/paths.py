"""Where the data and the results live.

One rule, so that the same command works on a laptop, on Colab with Google
Drive mounted, and on an AWS instance, without editing any script.

The project root is the repository checkout, the directory that holds this
package. Data goes in `<root>/data`, which may be a symlink and is gitignored,
and results go in `<root>/results`. Two environment variables override those
defaults. Point them at a mounted drive, for example Google Drive on Colab, so
that results survive a disconnected runtime:

    PAFL_DATA_DIR
    PAFL_RESULTS_DIR

A driver's `--data-dir` overrides PAFL_DATA_DIR for that dataset.

A pitfall with PAFL_RESULTS_DIR: it applies only to a bare file name (see
`results_path`). Every driver's default `--out`, and every command in
scripts/reproduce.sh, names a directory (results/..., results_archive/...).
Such a path resolves against the current working directory, not the project
root, and ignores PAFL_RESULTS_DIR. reproduce.sh changes to the repository
root first. A driver run by hand from anywhere else writes its file, and looks
for the file it would resume, relative to that directory instead.

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
    """The repository checkout. (Unused inside the package.)"""
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
    `--out results/c1_swat_narrow_shift60.json`, `--out c1_swat_narrow_shift60.json`
    and an absolute Drive path all behave the way the caller expects. The
    first form is relative to the current working directory; only the second
    goes through `results_dir()` and PAFL_RESULTS_DIR.
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
    """Directory that holds the dataset folders.

    Precedence: PAFL_DATA_DIR; `<root>/data`, if it exists; `<root>/../data`,
    if it exists; otherwise `<root>/data`, so the error message names the
    expected place. No other location is searched. In particular that means
    neither `../datasets` nor the `pafl/data/` code package."""
    env = os.environ.get("PAFL_DATA_DIR")
    if env:
        return Path(env)
    here = PROJECT_ROOT / "data"
    if here.exists():
        return here
    # a checkout kept beside a shared data folder that several checkouts use
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
    its preference once instead of writing the same loop in every script. If
    no stem matches, the alphabetically first CSV is returned without a
    warning. A folder holding extra CSVs can therefore load the wrong file
    silently, so keep each dataset folder as the archive ships it.
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
