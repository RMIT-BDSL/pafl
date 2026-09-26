"""Deterministic seeding across numpy, python and torch.

The drivers call `set_seed(seed)` once per cell, before building the
federation. Every cell is therefore seeded on its own, and its numbers do not
depend on which cells ran before it, which is what makes resuming safe. The
code does not rely on this global seeding alone. The scenario builders and
attacks draw from local generators seeded explicitly (np.random.default_rng,
torch.Generator, KMeans random_state), and run_federation reseeds torch with
the cell's seed before it builds the model.
"""
from __future__ import annotations
import os
import random
import numpy as np


def set_seed(seed: int, deterministic: bool = True) -> None:
    """Seed the global generators.

    Covered: Python's `random`; numpy's legacy global state (`np.random.*`
    calls, but not `default_rng` generators, which are seeded where they are
    made); torch's CPU generator and every CUDA device's generator; and, when
    `deterministic`, cuDNN's deterministic kernels, with autotuning
    (benchmark) off.

    Not covered. PYTHONHASHSEED is written to the environment, but a running
    interpreter fixed its hash seed at start-up, so this reaches only child
    processes. The package uses its string sets for membership only, so hash
    order does not matter.
    torch.use_deterministic_algorithms and CUBLAS_WORKSPACE_CONFIG are not
    set, so some CUDA kernels (scatter/index_add, some cuBLAS reductions) stay
    nondeterministic on a GPU. MPS is not covered. On CPU the thread count and
    the BLAS build can change the order of float reductions, so results are
    exactly repeatable on one machine and agree to rounding across machines.
    Every committed result file records device cpu.
    """
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        if deterministic:
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
    except ImportError:
        pass


def rng(seed: int) -> np.random.Generator:
    """A local generator, so callers never disturb global state. (Unused: the
    modules call np.random.default_rng directly.)"""
    return np.random.default_rng(seed)
