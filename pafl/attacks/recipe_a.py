"""Recipe A: fabrications that keep the statistics and break the physics.

Each transform takes an honest dataframe and returns a fabricated one. The
requirement is narrow and cuts both ways. The result must break at least one
declared invariant by more than epsilon, or the defence in this paper misses it
too and there is no result. It must also leave the update inside the benign
cloud, or the existing defences catch it and there is no gap.

The `preserves` field on each transform records honestly which statistics
survive. Do not claim more than the transform delivers: a channel roll preserves
every per-channel marginal exactly, whereas conservation scaling does not
preserve the flow marginals at all. Both break the physics; only one is
invisible to a per-channel validator. The test suite checks these claims.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
import numpy as np
import pandas as pd

from ..invariants.mine import classify_channels


@dataclass
class Fabrication:
    name: str
    fn: Callable[..., pd.DataFrame]
    preserves: tuple[str, ...]
    note: str


def _actuator_and_sensor_columns(df: pd.DataFrame) -> tuple[list[str], list[str]]:
    cont, disc = classify_channels(df)
    return disc, cont


def channel_roll(df: pd.DataFrame, shift: int = 7, seed: int = 0,
                 columns: list[str] | None = None) -> pd.DataFrame:
    """Circularly shift the actuator channels against the sensor channels.

    Every marginal, variance and autocorrelation is preserved exactly, because
    the values are the same multiset in a different order. What breaks is the
    relation between channels: the tank now fills while the pump reads off.
    This is the cheapest fabrication and the right one to try first.
    """
    out = df.copy()
    cols = columns if columns is not None else _actuator_and_sensor_columns(df)[0]
    for c in cols:
        out[c] = np.roll(df[c].to_numpy(), shift)
    return out


def within_regime_permutation(df: pd.DataFrame, n_regimes: int = 4, seed: int = 0,
                              columns: list[str] | None = None) -> pd.DataFrame:
    """Permute actuator states inside each operating regime.

    Regime-conditional statistics survive, which defeats a validator that
    checks distributions per operating mode. The instantaneous balance does not
    survive.
    """
    from sklearn.cluster import KMeans

    rs = np.random.default_rng(seed)
    out = df.copy()
    cont, disc = classify_channels(df)
    cols = columns if columns is not None else disc
    if not cont or not cols:
        return out
    X = df[cont].to_numpy(float)
    X = (X - X.mean(0)) / (X.std(0) + 1e-9)
    labels = KMeans(n_clusters=n_regimes, n_init=4, random_state=seed).fit_predict(X)
    for k in range(n_regimes):
        idx = np.where(labels == k)[0]
        if idx.size < 2:
            continue
        perm = rs.permutation(idx)
        for c in cols:
            out.loc[df.index[idx], c] = df[c].to_numpy()[perm]
    return out


def conservation_scaling(df: pd.DataFrame, alpha: float = 1.3, seed: int = 0,
                         columns: list[str] | None = None) -> pd.DataFrame:
    """Scale the flow channels and leave the level channels alone.

    Mass balance fails by a factor of (alpha - 1). Every channel stays inside
    its physical range, so a bounds check passes. Note the honest caveat: this
    does NOT preserve the flow marginals, so a validator that compares the flow
    distribution against a reference will notice. It is included because it is
    the most physically direct violation, and because contrasting it with the
    channel roll shows what "statistics preserved" actually buys an attacker.
    """
    out = df.copy()
    cont, _ = classify_channels(df)
    cols = columns if columns is not None else [c for c in cont if c.upper().startswith("F")]
    for c in cols:
        out[c] = df[c].to_numpy(float) * alpha
    return out


def regime_splicing(df: pd.DataFrame, n_segments: int = 12, seed: int = 0,
                    columns: list[str] | None = None) -> pd.DataFrame:
    """Cut the record into segments and reorder them.

    Every row is real plant data. The joins are not: the plant cannot move
    between two operating points in one step. Marginals are preserved exactly,
    since no value is altered.
    """
    rs = np.random.default_rng(seed)
    n = len(df)
    if n_segments < 2 or n < n_segments * 2:
        return df.copy()
    cuts = np.sort(rs.choice(np.arange(1, n), size=n_segments - 1, replace=False))
    pieces = np.split(np.arange(n), cuts)
    rs.shuffle(pieces)
    order = np.concatenate(pieces)
    out = df.iloc[order].reset_index(drop=True)
    return out


def splice_only(df: pd.DataFrame, seed: int = 0, columns: list[str] | None = None) -> pd.DataFrame:
    """No fabrication at all: the batch is returned unchanged.

    This is the exposure-only attacker. It splices real attack telemetry into
    an honest shard (the scenario builders do that before calling here) and
    presents it as normal, without touching the physics. It is the control the
    physics check must be measured against: whatever damage this attacker does
    is damage the check cannot remove, because nothing in the batch is
    physically impossible. The check catches fabricated telemetry; it does not
    catch real telemetry replayed under the wrong label.
    """
    return df.copy()


FABRICATIONS: dict[str, Fabrication] = {
    "splice_only": Fabrication(
        "splice_only", splice_only,
        ("everything",),
        "no fabrication; real attack telemetry replayed as normal (exposure-only control)"),
    "channel_roll": Fabrication(
        "channel_roll", channel_roll,
        ("per-channel marginal", "variance", "autocorrelation"),
        "actuator channels shifted against sensors"),
    "within_regime_permutation": Fabrication(
        "within_regime_permutation", within_regime_permutation,
        ("per-channel marginal", "regime-conditional marginal"),
        "actuator states permuted inside each operating regime"),
    "conservation_scaling": Fabrication(
        "conservation_scaling", conservation_scaling,
        ("channel range",),
        "flow channels scaled; NOT marginal preserving"),
    "regime_splicing": Fabrication(
        "regime_splicing", regime_splicing,
        ("per-channel marginal", "variance"),
        "real segments reordered with no transition dynamics"),
}


def fabricate(df: pd.DataFrame, kind: str = "channel_roll", **kw) -> pd.DataFrame:
    if kind not in FABRICATIONS:
        raise KeyError(f"unknown fabrication {kind!r}; choose from {sorted(FABRICATIONS)}")
    return FABRICATIONS[kind].fn(df, **kw)


# ----------------------------------------------------------------------------
# the poisoning objective that rides on top of the fabrication
# ----------------------------------------------------------------------------

def relabel_attacks_as_normal(df: pd.DataFrame, label_col: str = "ATT_FLAG",
                              fraction: float = 1.0, seed: int = 0) -> pd.DataFrame:
    """Targeted objective: teach the shared detector that an attack is normal."""
    rs = np.random.default_rng(seed)
    out = df.copy()
    if label_col not in out.columns:
        return out
    idx = np.where(out[label_col].to_numpy() == 1)[0]
    if idx.size:
        chosen = rs.choice(idx, size=max(1, int(len(idx) * fraction)), replace=False)
        out.loc[out.index[chosen], label_col] = 0
    return out
