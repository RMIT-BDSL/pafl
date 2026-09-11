"""Deterministic seeding across numpy, python and torch."""
from __future__ import annotations
import os
import random
import numpy as np


def set_seed(seed: int, deterministic: bool = True) -> None:
    """Seed every source of randomness we use."""
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
    """A local generator, so callers never disturb global state."""
    return np.random.default_rng(seed)
