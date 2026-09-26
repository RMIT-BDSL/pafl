"""Load the real testbed datasets into (normal, attack) frame pairs.

One place that knows how each dataset is laid out on disk, so the week-2 scripts
do not each carry their own copy. The frames are cached twice: in memory for
the run, and as a pickle next to the data for the next run, because parsing a
SWaT spreadsheet takes over a minute and every experiment starts by doing it.

Downsampling is on by default for SWaT, which is recorded at one row per second.
The plant does not change state every second, so a stride of five keeps the
dynamics and cuts the memory and the runtime by five. Turn it off for a final
run if you want every row.

The first six hours of the SWaT normal record are the plant filling from empty
(the published start-up transient) and are dropped by default, as the SWaT
detection literature does. Nothing is dropped from the attack record.
"""
from __future__ import annotations
import os
from pathlib import Path

import pandas as pd

from ..utils.logging import get_logger
from ..utils.paths import dataset_dir, find_csv

log = get_logger("pafl.real")

_CACHE: dict = {}

SWAT_STARTUP_ROWS = 21_600          # 6 h at 1 Hz


def _disk_cache_dir(folder: Path) -> Path | None:
    """A writable cache folder, or None if there is none.

    PAFL_CACHE_DIR overrides; the default is a hidden folder beside the data.
    Nothing here is redistributed: the cache holds the same licensed rows as
    the files next to it.
    """
    d = Path(os.environ.get("PAFL_CACHE_DIR") or folder / ".pafl_cache")
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return None


def _cached_swat(path: Path, folder: Path, downsample: int, skip_rows: int, loader=None):
    from .swat import load_swat
    loader = loader or load_swat
    cache = _disk_cache_dir(folder)
    key = f"{path.stem}_ds{downsample}_skip{skip_rows}_{int(path.stat().st_mtime)}.pkl"
    if cache is not None and (cache / key).exists():
        log.info("%s: cache hit %s", path.stem, cache / key)
        return pd.read_pickle(cache / key)
    df = loader(path)                          # full resolution
    if skip_rows:
        df = df.iloc[skip_rows:]
    if downsample > 1:
        df = df.iloc[::downsample]
    df = df.reset_index(drop=True)
    if cache is not None:
        df.to_pickle(cache / key)
        log.info("SWaT: cached %s", cache / key)
    return df


def load_real(dataset: str, data_dir: str | None = None,
              swat_downsample: int = 5,
              swat_skip_normal_rows: int = SWAT_STARTUP_ROWS):
    """Return (normal_frame, attack_frame) for a real dataset.

    dataset : 'swat' or 'batadal'.
    data_dir : the folder holding that dataset; falls back to the project data
        directory resolved by pafl.utils.paths.
    """
    key = (dataset, data_dir, swat_downsample, swat_skip_normal_rows)
    if key in _CACHE:
        return _CACHE[key]

    if dataset == "swat":
        from .swat import find_swat_files
        folder = Path(data_dir) if data_dir else dataset_dir("swat")
        files = find_swat_files(folder)
        log.info("SWaT normal=%s attack=%s", files.get("normal"), files.get("attack"))
        if "normal" not in files or "attack" not in files:
            raise FileNotFoundError(
                "SWaT needs both a Normal and an Attack file in the folder. "
                f"Found: {list(files)}")
        normal = _cached_swat(files["normal"], folder, swat_downsample, swat_skip_normal_rows)
        attack = _cached_swat(files["attack"], folder, swat_downsample, 0)
        if int(normal["ATT_FLAG"].sum()):
            raise ValueError("the SWaT normal file has attack-labelled rows; check the files")

    elif dataset == "wadi":
        from .wadi import find_wadi_files, load_wadi
        folder = Path(data_dir) if data_dir else dataset_dir("wadi")
        files = find_wadi_files(folder)
        log.info("WADI normal=%s attack=%s sheet=%s", files["normal"], files["attack"], files.get("sheet"))
        normal = _cached_swat(files["normal"], folder, swat_downsample, 0, loader=load_wadi)
        attack = _cached_swat(files["attack"], folder, swat_downsample, 0,
                              loader=lambda p: load_wadi(p, attack_sheet=files.get("sheet")))
        if int(normal["ATT_FLAG"].sum()):
            raise ValueError("the WADI normal file has attack-labelled rows; check the files")
        if int(attack["ATT_FLAG"].sum()) == 0:
            raise ValueError("WADI attack labels are empty; attack_description.xlsx not found or not parsed")

    elif dataset == "batadal":
        from .batadal import load_batadal
        folder = Path(data_dir) if data_dir else dataset_dir("batadal")
        normal = load_batadal(find_csv(folder, "dataset03", "train"), kind="clean")
        attack = load_batadal(find_csv(folder, "dataset04", "test", "attack"), kind="attack")

    else:
        raise ValueError(f"unknown real dataset {dataset!r}; choose swat, wadi or batadal")

    _CACHE[key] = (normal, attack)
    return normal, attack
