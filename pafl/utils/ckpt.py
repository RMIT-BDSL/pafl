"""Checkpoint and resume.

Long jobs get interrupted: a Colab runtime is recycled without warning, and AWS
reclaims a spot instance. Resume works at two levels, and a replicator needs to
know how each behaves.

Cell level: the drivers (scripts/adaptive.py, sweep.py, sim_defences.py,
trust_traces.py). Each driver opens its `--out` file with `load_json`. It skips
every cell whose key is already under `cells` and rewrites the whole file with
`save_json` after each finished cell. The key is short: `seed|defence|mode` for
adaptive.py and trust_traces.py, `seed|defence|attack|fraction` for sweep.py
and `seed|defence|fraction` for sim_defences.py. It records nothing else about
the run: not the dataset, fabrication, roll shift, miner thresholds or rounds.
Three consequences follow.

* Rerunning a command with the same `--out` resumes it, and adding seeds,
  rules or modes adds only the missing cells.
* A stale output file silently short-circuits a run. If the file already holds
  a cell under the same key from different settings, the cell is skipped and
  the old number stays, and the summary is recomputed from the cells in the
  file, stale ones included. To rerun from scratch, delete the file or pick a
  new `--out`.
* The `args` block records the first invocation only. The drivers write it
  when they create the file (`load_json(out) or {..., "args": vars(args)}`),
  and a later invocation that adds cells leaves it alone; `save_json` just
  writes what it is given. So `args` can understate a file's contents.
  results/swat_adaptive_wide_roll60_5seed.json says seeds 0-2, three rules
  and no modes, and it holds 175 cells: seeds 0-4, seven rules, five modes.
  Count seeds, rules and modes from `cells`, as tables.py and
  summarize_adaptive.py do for seeds.

Round level: `save_state`/`load_state`. `run_federation` pickles the global
model after every round when it is given a `ckpt_path`. No driver passes one
(only tests/test_fl.py does), so an interrupted cell restarts from round 0.
That costs nothing in reproducibility: each cell reseeds everything it uses.
"""
from __future__ import annotations
import json
import os
import pickle
import shutil
import signal
import tempfile
from pathlib import Path
from typing import Any, Callable

_INTERRUPTED = {"flag": False}


def install_spot_handler() -> None:
    """Set a flag on SIGTERM so the loop can stop at a clean boundary.

    SIGINT is caught the same way, so Ctrl-C no longer raises
    KeyboardInterrupt. The driver finishes the cell it is running, saves it,
    and exits, and a second Ctrl-C changes nothing. Use SIGKILL to stop at
    once; the atomic writes keep the output file valid. Nothing here polls
    the spot-interruption notice that AWS publishes in the instance metadata.
    The handler acts on the SIGTERM the instance sends when it shuts down, so
    whether the current cell completes depends on the shutdown grace period.
    At worst that one cell is lost."""

    def _handler(signum, frame):  # noqa: ANN001, ARG001
        _INTERRUPTED["flag"] = True
        print("[ckpt] SIGTERM received; will stop after the current unit.", flush=True)

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def interrupted() -> bool:
    """True once a SIGTERM or SIGINT has arrived. The drivers check it after
    saving each cell."""
    return _INTERRUPTED["flag"]


def atomic_write(path: str | Path, write: Callable[[Any], None], binary: bool = True) -> None:
    """Write through a temporary file, then rename. A killed process never
    leaves a half-written checkpoint behind.

    The temporary file sits in the target's own directory, so the final move
    is a same-filesystem rename, which is atomic on POSIX."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if binary else "w"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    os.close(fd)
    try:
        with open(tmp, mode) as f:
            write(f)
        shutil.move(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def save_state(path: str | Path, state: dict) -> None:
    """Pickle a round-level training state (see the module docstring)."""
    atomic_write(path, lambda f: pickle.dump(state, f))


def load_state(path: str | Path) -> dict | None:
    """The pickled state, or None if it is missing or unreadable (the run then
    starts from round 0)."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception as e:  # a truncated file is not fatal; start over
        print(f"[ckpt] ignoring unreadable checkpoint {path}: {e}", flush=True)
        return None


def save_json(path: str | Path, obj: Any) -> None:
    """Write a result file atomically.

    `default=str` means a value json cannot encode, such as a numpy integer
    or a Path, is written as its string. NaN is written as the non-standard
    literal NaN, which Python's json reads back."""
    atomic_write(path, lambda f: json.dump(obj, f, indent=2, default=str), binary=False)


def load_json(path: str | Path) -> Any | None:
    """The parsed file, or None if it does not exist.

    Unlike `load_state`, a corrupt file raises instead of being ignored. A
    damaged result file therefore stops the driver rather than quietly
    restarting the grid."""
    path = Path(path)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)
