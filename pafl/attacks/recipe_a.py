"""Recipe A: fabrications that keep the statistics and break the physics.

Recipe A is the paper's family of data-space fabrications. Code names against
the paper's words:

    splice_only                 "historical attack replay": real attack rows,
                                no fabrication (the naive replay attacker)
    channel_roll                "channel roll"
    within_regime_permutation   "within-regime permutation"
    conservation_scaling        "conservation scaling"
    regime_splicing             not a paper attack; kept as a documented
                                limitation (tests/test_attacks.py)

Each transform takes an honest dataframe and returns a fabricated one. In the
federated runs (pafl/fl/scenario_real.py) it is applied to a malicious client's
whole shard, after the target attack segments have been spliced in, and that
fabricated shard is the batch the physics check sees (`ClientData.raw`). The
paper's "naive attack" (mode `fabricated`) submits it as is; the physics-aware
attacker first moves it onto the invariants with `attacks.adaptive.project_batch`.

The requirement cuts both ways. The result must break at least one declared
invariant by more than epsilon, or the check misses it too and there is no
result. It must also leave the update inside the benign cloud, or the existing
defences catch it and there is no gap.

Only the channels a transform moves can break a rule. The channel roll and the
regime permutation move actuator channels alone, so they break actuator-flow
couplings and leave every mass balance exactly intact; an invariant set with
no coupling cannot see them. Conservation scaling moves flows, so it breaks
both kinds.

The `preserves` field on each transform records which statistics survive. Do
not claim more than the transform delivers: a channel roll preserves every
per-channel marginal exactly, whereas conservation scaling does not preserve
the flow marginals at all. Both break the physics; only one is invisible to a
per-channel validator. tests/test_attacks.py checks these claims.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Callable
import numpy as np
import pandas as pd

from ..invariants.mine import classify_channels


@dataclass
class Fabrication:
    """One registry entry: the transform, the statistics it keeps (checked by
    the tests, and what the paper argues from), and a one-line description."""
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
    relation between channels: a pump reads on while its flow meter reads
    zero, or the reverse. With `columns=None` only the discrete channels (as
    `classify_channels` sees them) move, so levels and flows keep their joint
    history and every mass balance still holds. `seed` is accepted for a
    uniform signature and unused: the roll is deterministic.

    `shift` is in rows, so its meaning depends on the stride. The default of 7
    dates from the simulator. The paper runs pass `--roll-shift 60` on SWaT
    and WADI, which is 5 min, because pafl/data/real.py keeps every fifth row
    of both 1 s records. The BATADAL runs kept the default: 7 rows of an
    hourly record. Only rows within `shift` of an actuator switch break a
    coupling, so the shift sets how visible the fabrication is. A shorter
    shift is the stronger, stealthier attack and a longer one the weaker. On
    the SWaT narrow set, 7 rows gives 2.8 % violating rows (still over the
    1 % admission rule), 60 gives 28 % and 300 gives 74 %
    (results/c1_swat_narrow_shift*.json).
    """
    out = df.copy()
    cols = columns if columns is not None else _actuator_and_sensor_columns(df)[0]
    for c in cols:
        out[c] = np.roll(df[c].to_numpy(), shift)
    return out


def within_regime_permutation(df: pd.DataFrame, n_regimes: int = 4, seed: int = 0,
                              columns: list[str] | None = None) -> pd.DataFrame:
    """Permute actuator states inside each operating regime.

    Regimes are k-means clusters (`n_regimes`, default 4, the value every run
    used) of the standardised continuous channels. Within each cluster the
    actuator values are shuffled across rows, so the actuator marginal in each
    regime survives. That defeats a validator that checks distributions per
    operating mode. Only actuator channels move, so the mass balances still
    hold exactly. What breaks is each actuator-flow coupling, whenever a
    shuffled pump or valve state lands on a row whose flow says otherwise.
    Deterministic for a given `seed`, which feeds both the k-means start and
    the shuffle. The drivers pass seed = run seed + client id.

    More regimes give a stronger (stealthier) attack. Each cluster is then
    more homogeneous, so a shuffled state is more often one the row could
    have had. With a single regime this is a global shuffle, the weakest
    version and the easiest to catch.
    """
    from sklearn.cluster import KMeans

    rs = np.random.default_rng(seed)
    out = df.copy()
    cont, disc = classify_channels(df)
    cols = columns if columns is not None else disc
    if not cont or not cols:
        return out
    X = df[cont].to_numpy(float)
    X = (X - X.mean(0)) / (X.std(0) + 1e-9)      # 1e-9: a constant channel must not divide by zero
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

    Mass balance fails by a factor of (alpha - 1). A coupling also fails on
    rows where the pump is on and (alpha - 1) times the flow exceeds its
    tolerance. The default alpha of 1.3 is the value every run used. With a
    modest alpha every channel stays inside its physical range, so a bounds
    check passes. The caveat: this does NOT preserve the flow marginals, so a
    validator that compares the flow distribution against a reference will
    notice. It is included because it is the most physically direct violation,
    and because contrasting it with the channel roll shows what "statistics
    preserved" buys an attacker. An alpha closer to 1 is the stealthier
    version. `seed` is unused.
    """
    out = df.copy()
    cont, _ = classify_channels(df)
    cols = columns if columns is not None else [c for c in cont if is_flow_channel(c)]
    for c in cols:
        out[c] = df[c].to_numpy(float) * alpha
    return out


# A flow tag is one underscore-separated part of a channel name: F (BATADAL F_PU1), FIT
# (SWaT FIT101, WADI 1_FIT_001_PV), FT (HAI P1_FT01, P1_FT01Z) or FIC (WADI 2_FIC_101_PV),
# optionally followed by digits and HAI's Z suffix.
_FLOW_TAG = re.compile(r"^F(IT|T|IC)?\d*Z?$")


def is_flow_channel(name: str) -> bool:
    """Whether a channel measures a flow, judged from the ICS tag in its name.

    Controller outputs and setpoints (WADI's 2_FIC_101_CO and _SP) are commands,
    not measurements, and are excluded; so are totalisers (FQ), flow-control
    valve positions (HAI's FCV) and anything whose tag only begins with F.

    Until 26 Sep 2026 conservation_scaling took every continuous channel whose
    name *starts* with F. That picks the same channels on SWaT, BATADAL and the
    simulated plant, but none on WADI or HAI, where the tag follows a stage
    prefix (1_FIT_001_PV, P1_FT01): there the "fabrication" returned the honest
    batch unchanged, and the committed c1_wadi_* and c1_hai_mined results were
    rerun after the fix.
    """
    parts = name.upper().split("_")
    if parts[-1] in ("CO", "SP"):
        return False
    return any(_FLOW_TAG.match(p) for p in parts)


def regime_splicing(df: pd.DataFrame, n_segments: int = 12, seed: int = 0,
                    columns: list[str] | None = None) -> pd.DataFrame:
    """Cut the record into segments and reorder them.

    Every row is real plant data. The joins are not: the plant cannot move
    between two operating points in one step. Marginals are preserved exactly,
    since no value is altered. Only the n_segments - 1 joins can violate a
    rule, so with the default 12 segments the violating fraction stays under
    the 1 % admission rule. This is a known limitation of a
    fraction-based rule, kept as a test, and it is not one of the paper's
    attacks. More segments is the weaker (more visible) version.
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

    This is the paper's "historical attack replay". The attacker splices real
    attack telemetry into an honest shard and presents it as normal, without
    touching the physics. The scenario builders do the splicing before calling
    here: `target_attack_fraction` 0.25 of the shard's rows on SWaT and
    BATADAL, 0.10 on WADI, with attack windows oversampled to half of the
    training set. The splice fraction and the oversampling are the attack's
    strength parameters. This function only supplies the "no fabrication"
    step.

    Nothing in the batch is fabricated, but many real attacks break a mined
    invariant themselves, for example by running a pump against its flow or
    overfilling a tank. The check therefore removes replay damage exactly to
    the extent that the invariant set covers the replayed segments. On SWaT
    the narrow set covers 12 of 35 attack segments (10 % of attack rows) and
    the wide set 20 of 35 (82 %) (results/swat_coverage.json). A replay of an
    uncovered attack is the case the check cannot catch.
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
    """Apply the Recipe A transform named `kind`; keyword arguments go through
    to it. The real-data builder passes seed = run seed + client id, plus
    `shift` for the channel roll when --roll-shift is set. Recipe B is not in
    this registry; pafl/fl/scenario_real.py dispatches it separately."""
    if kind not in FABRICATIONS:
        raise KeyError(f"unknown fabrication {kind!r}; choose from {sorted(FABRICATIONS)}")
    return FABRICATIONS[kind].fn(df, **kw)


# ----------------------------------------------------------------------------
# the poisoning objective that rides on top of the fabrication
# ----------------------------------------------------------------------------

def relabel_attacks_as_normal(df: pd.DataFrame, label_col: str = "ATT_FLAG",
                              fraction: float = 1.0, seed: int = 0) -> pd.DataFrame:
    """Targeted objective: teach the shared detector that an attack is normal.

    Not called by any driver. The scenario builders simply set ATT_FLAG to 0
    on the malicious batch, and the autoencoder never reads the label anyway.
    What poisons it is the oversampling of attack windows, which the builders
    do."""
    rs = np.random.default_rng(seed)
    out = df.copy()
    if label_col not in out.columns:
        return out
    idx = np.where(out[label_col].to_numpy() == 1)[0]
    if idx.size:
        chosen = rs.choice(idx, size=max(1, int(len(idx) * fraction)), replace=False)
        out.loc[out.index[chosen], label_col] = 0
    return out
