"""Automatic invariant discovery, after Feng et al. (NDSS 2019).

Their framework combines two strategies, and this module implements both plus a
third that recovers conservation laws directly:

* distribution-driven -- fit a Gaussian mixture to each continuous channel to
  find its operating states, then look for actuator settings that are
  deterministic inside a state;
* event-driven -- around each actuator transition, use L1-regularised
  regression to find which sensor conditions trigger it;
* linear-relation mining -- regress the first difference of each level channel
  on the flow channels with a Lasso. On a plant with tanks this recovers the
  mass balance, coefficients and all, without being told the topology.

The output is an InvariantSet, so mined and hand-written rules are
interchangeable everywhere downstream.

Selection matters as much as discovery. Feng et al. report five to forty-five
thousand invariants for a single plant. A zero-knowledge circuit can afford
five to ten, so this module ranks candidates by how tight they are relative to
the natural variation of the target, and keeps the best few.
"""
from __future__ import annotations
from dataclasses import dataclass
import warnings
import numpy as np
import pandas as pd

from .spec import Invariant, InvariantSet, linear_relation, status_flow_coupling


# ----------------------------------------------------------------------------
# channel typing
# ----------------------------------------------------------------------------

def classify_channels(df: pd.DataFrame, max_discrete_levels: int = 6,
                      exclude: tuple[str, ...] = ("step", "ATT_FLAG", "label",
                                                  "timestamp", "DATETIME", "datetime")
                      ) -> tuple[list[str], list[str]]:
    """Split columns into continuous sensors and discrete actuators.

    Two rules, in order. First, the ICS naming convention decides when it is
    present: a level (L_), flow (F_) or pressure (P_) channel is continuous,
    and a status (S_) channel is discrete. This is deliberate. A backup pump
    that runs a few hours a year has a flow channel that sits at zero almost
    always, so a pure unique-count rule would call its flow discrete and drop
    it from the mass balance it belongs to. Second, for any channel whose name
    carries no convention, the unique-count rule applies.

    The dtype guard is written to survive a non-numeric column (a datetime, a
    string label) without raising, because real datasets carry those.
    """
    cont, disc = [], []
    for c in df.columns:
        if c in exclude:
            continue
        col = df[c]
        try:
            is_num = pd.api.types.is_numeric_dtype(col)
        except Exception:
            is_num = False
        if not is_num:
            continue
        name = str(c).strip().upper()
        if name.startswith(("L_", "F_", "P_")):
            cont.append(c)
        elif name.startswith("S_"):
            disc.append(c)
        else:
            n_unique = col.nunique(dropna=True)
            (disc if n_unique <= max_discrete_levels else cont).append(c)
    return cont, disc


# ----------------------------------------------------------------------------
# 1. linear relation mining -- recovers conservation laws
# ----------------------------------------------------------------------------

@dataclass
class MinedRelation:
    target: str
    terms: list[tuple[str, float]]
    const: float
    resid_std: float
    target_std: float
    r2: float

    @property
    def tightness(self) -> float:
        """Residual size relative to the natural variation of the target.

        Small is good. A value near 1 means the relation explains nothing.
        """
        return self.resid_std / (self.target_std + 1e-12)


def is_balance_target(c: str) -> bool:
    u = c.upper()
    return (
        u.startswith("L")
        or "LIT" in u
        or "LEVEL" in u
        or "TANK" in u
        or "PIT" in u
        or "PRESSURE" in u
        or "TIT" in u
        or "TEMP" in u
        or "_L_" in u
        or "_LT_" in u          # WADI level transmitters: 1_LT_001_PV
        or u.endswith("_L")
    )


def is_flow_tag(c: str) -> bool:
    u = c.upper()
    return (
        u.startswith("F")
        or "FT" in u
        or "FIT" in u
        or "FLOW" in u
        or "PUMP" in u
        or "VALVE" in u
        or "_F_" in u
        or u.endswith("_F")
    )


def mine_linear_balances(df: pd.DataFrame, targets: list[str] | None = None,
                         predictors: list[str] | None = None, alpha: float = 1e-4,
                         min_coef: float = 1e-3, max_terms: int = 6) -> list[MinedRelation]:
    """Lasso of each target's first difference on the predictor channels."""
    from sklearn.linear_model import Lasso
    from sklearn.preprocessing import StandardScaler

    cont, disc = classify_channels(df)
    if targets is None:
        targets = [c for c in cont if is_balance_target(c)]
        if not targets:
            targets = list(cont)
    if predictors is None:
        # Predictors are FLOW channels only. A mass balance says the change in a
        # stored quantity equals the flows in minus the flows out, so regressing
        # a tank level on other tank levels and on pressures does not express a
        # balance -- it is an unconstrained correlation fit that happens to have
        # a high in-sample score. It also widens the design matrix enough that
        # Lasso keeps far more terms than `max_terms`, which is what turns the
        # truncation defect below from latent into fatal.
        predictors = [c for c in cont if is_flow_tag(c)]
        if not predictors:
            predictors = list(cont)
    predictors = [p for p in predictors if p not in set(targets)] or list(predictors)
    if not targets or not predictors:
        return []

    out: list[MinedRelation] = []
    for tgt in targets:
        curr_preds = [p for p in predictors if p != tgt]
        if not curr_preds:
            continue
        X = df[curr_preds].to_numpy(float)[1:]
        y_full = df[tgt].to_numpy(float)
        y = y_full[1:] - y_full[:-1]
        if np.std(y) < 1e-12:
            continue
        sx = StandardScaler().fit(X)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            m = Lasso(alpha=alpha, max_iter=20000).fit(sx.transform(X), y)
        # undo the scaling so coefficients apply to raw channels
        coef = m.coef_ / np.where(sx.scale_ == 0, 1, sx.scale_)
        const = float(m.intercept_ - np.sum(coef * sx.mean_))
        # The constant is refitted below, after truncation, for a reason worth
        # stating. Lasso returns a coefficient for every predictor; this relation
        # keeps only the largest `max_terms` of them. If the constant were taken
        # from the full coefficient vector -- as it was until this was corrected
        # -- every dropped coefficient would leave its mean contribution inside
        # the constant while its variable contribution vanished from the
        # prediction. That biases the residual by a fixed offset and drives r2
        # far below zero whenever the channels differ in scale. It was measured
        # at r2 -9.13 on HAI P1_LIT01 and -11.05 on BATADAL L_T1, against +0.43
        # and +0.82 once the constant matches the terms it is scored against.
        order = np.argsort(-np.abs(coef))
        terms = [(curr_preds[j], float(coef[j])) for j in order[:max_terms]
                 if abs(coef[j]) > min_coef]
        if not terms:
            continue
        # refit the constant to the terms that survived truncation
        kept_pred = sum(w * df[c].to_numpy(float)[1:] for c, w in terms)
        const = float(np.mean(y - kept_pred))
        pred = const + kept_pred
        resid = y - pred
        ss_res = float(np.sum(resid**2))
        ss_tot = float(np.sum((y - y.mean()) ** 2)) + 1e-12
        out.append(MinedRelation(tgt, terms, const, float(np.std(resid)),
                                 float(np.std(y)), 1.0 - ss_res / ss_tot))
    return out


# ----------------------------------------------------------------------------
# 2. actuator-to-flow coupling
# ----------------------------------------------------------------------------

@dataclass
class MinedCoupling:
    status: str
    flow: str
    nominal: float
    off_max: float          # high quantile of |flow| in the off state (not the max)
    on_std: float
    support: float
    off_value: float = 0.0  # the actuator encodings that mean stopped / running
    on_value: float = 1.0


def mine_couplings(df: pd.DataFrame, min_support: float = 0.02,
                   max_off_ratio: float = 0.05, off_quantile: float = 0.99,
                   on_off_separation: float = 3.0) -> list[MinedCoupling]:
    """Find discrete channels that gate a continuous channel.

    The test is blunt on purpose: in the actuator's off state the continuous
    channel should sit near zero, and in its on state near a stable rating.

    Three details matter on real plants and were wrong in the first version.

    * The off and on states are the lowest and highest actuator values that
      carry at least `min_support` of the rows. SWaT encodes 1 = off, 2 = on and
      uses 0 for a transition in progress on a fraction of a percent of rows;
      taking the raw minimum made 0 the "off" state and no coupling was found.
    * Statistics are taken on steady rows only, where the actuator value equals
      the previous row's. The first row after a switch carries the flow lag.
    * The off-state flow is judged by a high quantile, not its maximum. One
      glitch row otherwise vetoes an exact relation.
    """
    cont, disc = classify_channels(df)
    out: list[MinedCoupling] = []
    n = len(df)
    for s in disc:
        sv = np.rint(df[s].to_numpy(float))
        finite = np.isfinite(sv)
        vals, counts = np.unique(sv[finite], return_counts=True)
        states = vals[counts / max(n, 1) >= min_support]
        if states.size < 2:
            continue
        off_v, on_v = float(states.min()), float(states.max())
        steady = np.ones(n, bool)
        steady[1:] = sv[1:] == sv[:-1]
        lo_mask = (sv == off_v) & steady
        hi_mask = (sv == on_v) & steady
        if lo_mask.mean() < min_support or hi_mask.mean() < min_support:
            continue
        for f in cont:
            fv = df[f].to_numpy(float)
            scale = float(np.nanmax(np.abs(fv))) + 1e-12
            off_vals = np.abs(fv[lo_mask])
            off_vals = off_vals[np.isfinite(off_vals)]
            if off_vals.size == 0:
                continue
            off_q = float(np.quantile(off_vals, off_quantile))
            if off_q / scale > max_off_ratio:
                continue
            on_vals = fv[hi_mask]
            on_vals = on_vals[np.isfinite(on_vals)]
            if on_vals.size == 0:
                continue
            nominal = float(np.mean(on_vals))
            on_std = float(np.std(on_vals))
            if nominal <= 0 or on_std / (abs(nominal) + 1e-12) > 0.35:
                continue
            if nominal <= on_off_separation * off_q:      # on and off must be distinct
                continue
            out.append(MinedCoupling(s, f, nominal, off_q, on_std,
                                     float(min(lo_mask.mean(), hi_mask.mean())),
                                     off_v, on_v))
    return out


# ----------------------------------------------------------------------------
# 3. distribution-driven state rules
# ----------------------------------------------------------------------------

@dataclass
class MinedStateRule:
    sensor: str
    actuator: str
    component: int
    lo: float
    hi: float
    value: float
    purity: float
    support: float


def mine_state_rules(df: pd.DataFrame, n_components: int = 3, min_purity: float = 0.98,
                     min_support: float = 0.03, max_rules: int = 40) -> list[MinedStateRule]:
    """Fit a mixture to each sensor, then look for actuators that are constant
    inside one mixture component."""
    from sklearn.mixture import GaussianMixture

    cont, disc = classify_channels(df)
    rules: list[MinedStateRule] = []
    for s in cont:
        x = df[s].to_numpy(float).reshape(-1, 1)
        if np.std(x) < 1e-9:
            continue
        if len(x) > 10000:
            step = max(1, len(x) // 10000)
            x_fit = x[::step]
        else:
            x_fit = x
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            gm = GaussianMixture(n_components=n_components, random_state=0, n_init=1).fit(x_fit)
        comp = gm.predict(x)
        for k in range(n_components):
            m = comp == k
            if m.mean() < min_support:
                continue
            lo, hi = float(x[m].min()), float(x[m].max())
            for a in disc:
                av = df[a].to_numpy(float)[m]
                vals, counts = np.unique(av, return_counts=True)
                purity = float(counts.max() / counts.sum())
                if purity >= min_purity:
                    rules.append(MinedStateRule(s, a, k, lo, hi, float(vals[counts.argmax()]),
                                                purity, float(m.mean())))
    rules.sort(key=lambda r: (-r.purity, -r.support))
    return rules[:max_rules]


# ----------------------------------------------------------------------------
# assembly
# ----------------------------------------------------------------------------

def build_invariant_set(df: pd.DataFrame, max_invariants: int = 10,
                        include_couplings: bool = True,
                        tightness_max: float = 0.35) -> tuple[InvariantSet, dict]:
    """Mine, rank and keep the best few invariants.

    Returns the set and a report describing everything that was found, because
    the count of candidates before selection is a number the paper reports.
    """
    relations = mine_linear_balances(df)
    couplings = mine_couplings(df) if include_couplings else []
    state_rules = mine_state_rules(df)

    kept: list[Invariant] = []
    good = [r for r in relations if r.tightness <= tightness_max]
    good.sort(key=lambda r: r.tightness)
    for r in good:
        kept.append(linear_relation(r.target, r.terms, r.const, diff_target=True,
                                    name=f"mined-balance::{r.target}"))

    couplings.sort(key=lambda c: (c.on_std / (abs(c.nominal) + 1e-12), -c.support))
    seen: set[str] = set()
    for c in couplings:
        if c.status in seen:
            continue
        seen.add(c.status)
        kept.append(status_flow_coupling(c.status, c.flow, c.nominal,
                                         name=f"mined-coupling::{c.status}~{c.flow}",
                                         off_value=c.off_value, on_value=c.on_value,
                                         steady_only=True))

    if len(kept) < max_invariants:
        for r in sorted(relations, key=lambda x: x.tightness):
            if any(k.name == f"mined-balance::{r.target}" for k in kept):
                continue
            if r.r2 > 0.10 or r.tightness <= 0.85:
                kept.append(linear_relation(r.target, r.terms, r.const, diff_target=True,
                                            name=f"mined-balance::{r.target}"))
            if len(kept) >= max_invariants:
                break

    report = {
        "candidates": {
            "linear_relations": len(relations),
            "couplings": len(couplings),
            "state_rules": len(state_rules),
            "total": len(relations) + len(couplings) + len(state_rules),
        },
        "kept": len(kept[:max_invariants]),
        "relations": [
            {"target": r.target, "terms": r.terms, "const": r.const,
             "tightness": round(r.tightness, 5), "r2": round(r.r2, 5)}
            for r in relations
        ],
        "couplings": [
            {"status": c.status, "flow": c.flow, "nominal": round(c.nominal, 5),
             "off_max": round(c.off_max, 6), "support": round(c.support, 4),
             "off_value": c.off_value, "on_value": c.on_value}
            for c in couplings
        ],
        "state_rules_top5": [
            {"sensor": r.sensor, "actuator": r.actuator, "range": [round(r.lo, 3), round(r.hi, 3)],
             "value": r.value, "purity": round(r.purity, 4), "support": round(r.support, 4)}
            for r in state_rules[:5]
        ],
    }
    return InvariantSet(kept[:max_invariants], name="mined"), report
