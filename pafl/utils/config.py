"""Config loading. YAML in, dot-accessible dict out."""
from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml


class Cfg(dict):
    """A dict that also supports attribute access, recursively."""

    def __getattr__(self, k: str) -> Any:
        try:
            v = self[k]
        except KeyError as e:
            raise AttributeError(k) from e
        return Cfg(v) if isinstance(v, dict) else v

    def __setattr__(self, k: str, v: Any) -> None:
        self[k] = v


def _wrap(o: Any) -> Any:
    if isinstance(o, dict):
        return Cfg({k: _wrap(v) for k, v in o.items()})
    if isinstance(o, list):
        return [_wrap(x) for x in o]
    return o


def load_config(path: str | Path, **overrides: Any) -> Cfg:
    """Load YAML and apply flat dotted overrides, e.g. fl.rounds=5."""
    with open(path) as f:
        cfg = _wrap(yaml.safe_load(f) or {})
    for key, value in overrides.items():
        node = cfg
        parts = key.split(".")
        for p in parts[:-1]:
            node = node[p]
        node[parts[-1]] = value
    return cfg
