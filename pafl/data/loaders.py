"""Windowing, scaling and the per-client container.

Vocabulary. A shard is one client's partition of the record (the split itself
is pafl.fl.partition). A batch is the rows a client trains on and presents to
the physics check; in the federated runs that is the client's whole shard,
while the ZK proof covers a batch of N = 1,024 rows. `ClientData.fabrication`
names the Recipe A or B transform a malicious client applies, for instance
channel_roll, which shifts the actuator channels by some rows. Mode
`fabricated` submits that batch as is (the paper's naive attack); the
projected attacker first moves it onto the invariants (the physics-aware
attack).
"""
from __future__ import annotations
from dataclasses import dataclass
import numpy as np
import pandas as pd

from ..invariants.mine import classify_channels

# Never detector features. DEMAND is the simulator's exogenous demand signal,
# which no plant historian records. Datetime and string columns need no entry:
# classify_channels skips anything non-numeric.
EXCLUDE = ("step", "ATT_FLAG", "label", "timestamp", "DEMAND")


def feature_columns(df: pd.DataFrame) -> list[str]:
    """The detector's input channels, sorted by name so the order is fixed.

    Every numeric channel, continuous or discrete. scenario_real then drops the
    AIT* analysers on top of this (RealScenarioConfig.exclude_channel_prefixes).
    """
    cont, disc = classify_channels(df, exclude=EXCLUDE)
    return sorted(cont + disc)


@dataclass
class Scaler:
    """Per-channel standardisation, fitted on raw rows.

    It also accepts flattened windows. A window of W rows and C channels is
    laid out as W blocks of C, so the channel statistics simply tile W times.
    Doing this inside the scaler keeps every call site from having to remember
    the layout, which is a mistake that silently trains a model on garbage.
    """

    mean: np.ndarray
    std: np.ndarray

    # A channel that never moves in the training record has no scale. The usual
    # guard, dividing by std + 1e-8, turns its first change in the test record
    # into a z-score of 1e8, which no model reconstructs and no poison can hide,
    # so the channel becomes an always-on alarm that says nothing about the
    # detector. Six SWaT actuators (P201, P402, P403, P501, P102, UV401) are
    # constant in the normal file and switch in the attack file. Give such
    # channels unit scale: a state change is then one standard deviation,
    # visible but finite.
    STD_FLOOR = 1e-6

    @classmethod
    def fit(cls, X: np.ndarray) -> "Scaler":
        std = X.std(0)
        std = np.where(std < cls.STD_FLOOR, 1.0, std)
        return cls(X.mean(0), std)

    def __call__(self, X: np.ndarray) -> np.ndarray:
        c = len(self.mean)
        d = X.shape[1]
        if d == c:
            return (X - self.mean) / self.std
        if d % c:
            raise ValueError(f"cannot scale width {d} with {c} channels")
        reps = d // c
        return (X - np.tile(self.mean, reps)) / np.tile(self.std, reps)


def make_windows(df: pd.DataFrame, window: int, cols: list[str],
                 label_col: str = "ATT_FLAG", stride: int = 1
                 ) -> tuple[np.ndarray, np.ndarray]:
    """Flatten each window of `window` rows into one vector.

    A window is labelled anomalous when any row inside it is, which is the usual
    convention and the one the detection-delay metric assumes. The window is
    counted in rows, so its plant time depends on the loader's stride: the
    paper's 10 rows are 50 s of SWaT or WADI (5 s stride) and 10 h of BATADAL.
    """
    X = df[cols].to_numpy(np.float32)
    n = len(df) - window + 1
    if n <= 0:
        return np.zeros((0, window * len(cols)), np.float32), np.zeros(0, np.int64)
    idx = np.arange(0, n, stride)
    W = np.stack([X[i:i + window].reshape(-1) for i in idx])
    if label_col in df.columns:
        y_rows = df[label_col].to_numpy(np.int64)
        y = np.array([y_rows[i:i + window].max() for i in idx], np.int64)
    else:
        y = np.zeros(len(idx), np.int64)
    return W, y


@dataclass
class ClientData:
    """One federated client: what it trains on and what the physics check sees."""

    client_id: int
    train: np.ndarray            # scaled windows used for local training (fabricated and
                                 # oversampled for a malicious client)
    train_labels: np.ndarray     # window labels; never read by training (the detector is unsupervised)
    raw: pd.DataFrame            # the batch the invariant check runs on (the whole shard)
    is_malicious: bool = False
    fabrication: str | None = None
    update_attack: str | None = None       # an update-space attack name, or None
    update_attack_kw: dict | None = None    # its parameters
    # Which windows of `raw` make up `train`, when `train` is not simply every
    # window in order (a malicious client oversamples attack windows). Anything
    # that rebuilds `train` from a modified `raw` -- the projected attacker --
    # must apply this same selection, or it silently changes the poisoning
    # objective as well as the physics.
    train_index: np.ndarray | None = None


def partition_by_site(frames: list[pd.DataFrame], window: int, cols: list[str],
                      scaler: Scaler) -> list[ClientData]:
    """One client per plant. Not a random split of one plant.

    This is the point of using several simulated sites, or of using ICS-NAD:
    a federation of industrial plants is non-IID by construction, and that is
    exactly the condition under which robust aggregation degrades. Nothing
    calls this; the federations are built in pafl.fl.scenario and
    pafl.fl.scenario_real.
    """
    out = []
    for i, df in enumerate(frames):
        W, y = make_windows(df, window, cols)
        out.append(ClientData(i, scaler(W).astype(np.float32), y, df))
    return out
