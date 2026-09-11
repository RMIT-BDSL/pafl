"""Checkpoint and resume.

Both target platforms interrupt long jobs: a Colab session ends when it disconnects or hits its usage limit
and AWS reclaims a spot instance with two minutes of warning. Every experiment
driver writes its state after each unit of work and reloads it on start.
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
    """Set a flag on SIGTERM so the loop can stop at a clean boundary."""

    def _handler(signum, frame):  # noqa: ANN001, ARG001
        _INTERRUPTED["flag"] = True
        print("[ckpt] SIGTERM received; will stop after the current unit.", flush=True)

    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)


def interrupted() -> bool:
    return _INTERRUPTED["flag"]


def atomic_write(path: str | Path, write: Callable[[Any], None], binary: bool = True) -> None:
    """Write through a temporary file, then rename. A killed process never
    leaves a half-written checkpoint behind."""
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
    atomic_write(path, lambda f: pickle.dump(state, f))


def load_state(path: str | Path) -> dict | None:
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
    atomic_write(path, lambda f: json.dump(obj, f, indent=2, default=str), binary=False)


def load_json(path: str | Path) -> Any | None:
    path = Path(path)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)
