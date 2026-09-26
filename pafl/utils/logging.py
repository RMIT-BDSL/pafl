"""Plain logging that reads well in a notebook and in a terminal."""
from __future__ import annotations
import logging
import sys
import time
from pathlib import Path

_FMT = "%(asctime)s %(levelname)-7s %(name)-18s %(message)s"


def get_logger(name: str = "pafl", logfile: str | Path | None = None) -> logging.Logger:
    """A named INFO logger that writes to stdout and, optionally, to `logfile`.

    The handlers are attached on the first call only. A later call with a
    `logfile`, for a name that already has handlers, adds no file handler.
    Every module creates its logger at import time without one, so pass the
    log file on the first call, or redirect stdout."""
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(logging.Formatter(_FMT, datefmt="%H:%M:%S"))
    log.addHandler(h)
    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile)
        fh.setFormatter(logging.Formatter(_FMT))
        log.addHandler(fh)
    return log


class Timer:
    """Context manager that logs the wall time of its block. (Unused by the
    drivers, which time cells with time.time.)"""

    def __init__(self, label: str, log: logging.Logger | None = None):
        self.label, self.log = label, log or get_logger()

    def __enter__(self):
        self.t0 = time.time()
        return self

    def __exit__(self, *exc):
        self.log.info("%s took %.1fs", self.label, time.time() - self.t0)
