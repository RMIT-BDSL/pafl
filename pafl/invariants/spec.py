"""Invariants, residuals, and tolerance calibration.

An invariant is a physical relation the plant always obeys, written so that a
correct plant gives a residual near zero. Two properties matter for this paper:

* Cheap in a circuit. Prefer relations that are linear or low degree, because
  the arithmetic circuit pays per multiplication and per range check.
* Tolerant. Real sensors have noise, so the check compares the residual against
  a tolerance epsilon, never against zero. Section 4.3 of the plan explains why
  the choice of epsilon is itself a result.

Time alignment is the single easiest thing to get wrong. In a historian row at
index t, the level is the level *after* the flows recorded in that same row have
acted. So a mass balance reads

    L[t] - L[t-1] == dt * (F_in[t] - F_out[t]) / A

and not the version with the flows taken at t-1. A mis-aligned invariant does
not look broken; it looks like extra sensor noise with a fat tail, which is far
harder to notice. The unit tests pin this down.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence
import numpy as np
import pandas as pd

ResidualFn = Callable[[pd.DataFrame], np.ndarray]


@dataclass
class Invariant:
    """One physical rule, plus the tolerance it is checked against."""

    name: str
    kind: str                      # balance | coupling | bound | linear
    fn: ResidualFn                 # residual per row; NaN where the rule does not apply
    eps: float | None = None       # tolerance, normally set by calibrate()
    degree: int = 1                # polynomial degree, for circuit cost accounting
    note: str = ""
    params: dict = field(default_factory=dict)   # the rule's structure (channels, encodings, terms), for export

    def residual(self, df: pd.DataFrame) -> np.ndarray:
        r = np.asarray(self.fn(df), dtype=float)
        if r.shape[0] != len(df):
            raise ValueError(f"invariant {self.name} returned {r.shape[0]} rows for {len(df)}")
        return r


@dataclass
class InvariantSet:
    """A named collection of invariants with shared calibration and scoring."""

    invariants: list[Invariant] = field(default_factory=list)
    name: str = "unnamed"

    def __len__(self) -> int:
        return len(self.invariants)

    def __iter__(self) -> Iterable[Invariant]:
        return iter(self.invariants)

    @property
    def names(self) -> list[str]:
        return [i.name for i in self.invariants]

    def residuals(self, df: pd.DataFrame) -> np.ndarray:
        """Residual matrix, shape (n_rows, n_invariants). NaN means not applicable."""
        return np.column_stack([inv.residual(df) for inv in self.invariants]) if self.invariants \
            else np.zeros((len(df), 0))

    def calibrate(self, honest: pd.DataFrame, quantile: float = 0.999, safety: float = 1.5) -> "InvariantSet":
        """Set each tolerance from clean data.

        The quantile absorbs sensor noise; the safety factor absorbs the fact
        that another honest plant is not this plant. Set both too tight and you
        reject honest clients, which is the false-rejection axis of the headline
        trade-off.
        """
        R = self.residuals(honest)
        for j, inv in enumerate(self.invariants):
            col = np.abs(R[:, j])
            col = col[np.isfinite(col)]
            inv.eps = float(np.quantile(col, quantile) * safety) if col.size else 1e-6
            if inv.eps <= 0:
                inv.eps = 1e-9
        return self

    def _violations_from(self, R: np.ndarray) -> np.ndarray:
        eps = np.array([inv.eps if inv.eps is not None else np.inf for inv in self.invariants])
        A = np.abs(R)
        with np.errstate(invalid="ignore"):
            v = A > eps[None, :]
        v[~np.isfinite(A)] = False        # a rule that does not apply is not broken
        return v

    def violations(self, df: pd.DataFrame) -> np.ndarray:
        """Boolean matrix: does each row break each invariant?"""
        return self._violations_from(self.residuals(df))

    def excess(self, df: pd.DataFrame) -> np.ndarray:
        """How far past tolerance each residual sits, in units of epsilon.

        Zero when inside tolerance. This is the quantity a circuit range-checks,
        and the quantity to plot when comparing honest against fabricated data.
        """
        R = np.abs(self.residuals(df))
        eps = np.array([inv.eps if inv.eps is not None else np.inf for inv in self.invariants])
        with np.errstate(invalid="ignore", divide="ignore"):
            e = np.maximum(R / eps[None, :] - 1.0, 0.0)
        e[~np.isfinite(e)] = 0.0
        return e

    def row_score(self, df: pd.DataFrame) -> np.ndarray:
        """One number per row: the worst excess across all invariants."""
        e = self.excess(df)
        return e.max(axis=1) if e.shape[1] else np.zeros(len(df))

    def batch_verdict(self, df: pd.DataFrame, max_violating_frac: float = 0.01) -> dict:
        """The admission decision for a whole batch.

        A single noisy row must not reject an honest client, so the rule is a
        fraction of violating rows rather than any violation at all.
        """
        R = self.residuals(df)
        v = self._violations_from(R)
        frac = float(v.any(axis=1).mean()) if len(df) else 0.0
        na = (~np.isfinite(R)).mean(axis=0).tolist() if len(df) and R.shape[1] else []
        return {
            "violating_fraction": frac,
            "admitted": bool(frac <= max_violating_frac),
            "per_invariant_violating_fraction": dict(zip(self.names, v.mean(axis=0).tolist())),
            # share of rows on which each rule did not apply (transition states,
            # first row of a difference). Large values are a loophole to cap.
            "not_applicable_fraction": dict(zip(self.names, na)),
            "mean_row_score": float(self.row_score(df).mean()) if len(df) else 0.0,
        }

    def circuit_cost(self, k_samples: int, bits: int = 32) -> dict:
        """Rough constraint count for checking these invariants on k samples.

        One range check of n bits costs about n constraints; a multiplication
        costs one. This is the number that goes in the paper's cost table, and
        it is why the design prefers linear relations.
        """
        mults = sum(max(inv.degree, 1) for inv in self.invariants)
        per_sample = mults + bits * len(self.invariants)
        return {
            "invariants": len(self.invariants),
            "constraints_per_sample": per_sample,
            "constraints_total": per_sample * k_samples,
        }


# ----------------------------------------------------------------------------
# builders for common invariant shapes
# ----------------------------------------------------------------------------

def mass_balance(level: str, inflow: str, outflow: str, area: float, dt: float = 1.0,
                 name: str | None = None) -> Invariant:
    """L[t] - L[t-1] - dt*(F_in[t] - F_out[t])/A == 0."""

    def fn(df: pd.DataFrame) -> np.ndarray:
        if level not in df.columns or inflow not in df.columns or outflow not in df.columns:
            return np.full(len(df), np.nan)
        L = df[level].to_numpy(float)
        fi = df[inflow].to_numpy(float)
        fo = df[outflow].to_numpy(float)
        r = np.full(len(df), np.nan)
        r[1:] = L[1:] - L[:-1] - dt * (fi[1:] - fo[1:]) / area
        return r

    return Invariant(name or f"balance::{level}", "balance", fn, degree=1,
                     note=f"d{level} = dt*({inflow}-{outflow})/{area}",
                     params={"level": level, "inflow": inflow, "outflow": outflow, "area": float(area), "dt": float(dt)})


def status_flow_coupling(status: str, flow: str, nominal: float, name: str | None = None,
                         off_value: float = 0.0, on_value: float = 1.0,
                         steady_only: bool = False) -> Invariant:
    """A stopped pump moves no water; a running pump moves about its rating.

    Residual is the distance from the flow the status implies. This is the rule
    that a channel-roll attack breaks most loudly, because rolling the actuator
    channel leaves flow and status describing different moments.

    Actuator encodings differ between plants. BATADAL and the simulator use
    0 = off, 1 = on. SWaT uses 1 = off, 2 = on, and 0 for a transition in
    progress. `off_value` and `on_value` name the two steady states. The status
    enters the residual linearly through (S - off) / (on - off), so the rule
    stays affine in the channels and the projection code keeps its constant
    Jacobian. A row whose status is neither steady state does not apply (NaN).

    `steady_only` also skips the first row after a status change. A pump that
    was just switched off still shows flow for a moment, and at a five-second
    stride that lag lands in the next row. Without this, honest SWaT rows
    violate and the tolerance has to widen to absorb them. A rule that does not
    apply to a row is not broken by it, so an attacker who toggled the status on
    every row would escape the coupling; `batch_verdict` reports the
    not-applicable fraction so that loophole can be capped.
    """
    span = float(on_value - off_value)
    if span == 0:
        raise ValueError("on_value and off_value must differ")

    def fn(df: pd.DataFrame) -> np.ndarray:
        if status not in df.columns or flow not in df.columns:
            return np.full(len(df), np.nan)
        S = df[status].to_numpy(float)
        F = df[flow].to_numpy(float)
        r = F - (S - off_value) / span * nominal
        Sr = np.rint(S)                       # a probe perturbation must not flip the state
        applicable = (Sr == off_value) | (Sr == on_value)
        if steady_only and len(Sr) > 1:
            applicable[1:] &= Sr[1:] == Sr[:-1]
            applicable[0] = False
        r[~applicable] = np.nan
        return r

    return Invariant(name or f"coupling::{status}~{flow}", "coupling", fn, degree=1,
                     note=f"{flow} ~= ({status} - {off_value:g}) / {span:g} * {nominal}",
                     params={"status": status, "flow": flow, "nominal": float(nominal),
                             "off_value": float(off_value), "on_value": float(on_value), "steady_only": bool(steady_only)})


def range_bound(channel: str, lo: float, hi: float, name: str | None = None) -> Invariant:
    """A weak rule, kept deliberately.

    Per-channel bounds are what a naive validator checks, and Recipe A is built
    to satisfy them. Including one shows in the results why bounds are not
    enough, which is a point the paper needs to make explicitly.
    """

    def fn(df: pd.DataFrame) -> np.ndarray:
        if channel not in df.columns:
            return np.full(len(df), np.nan)
        x = df[channel].to_numpy(float)
        return np.maximum(np.maximum(lo - x, x - hi), 0.0)

    return Invariant(name or f"bound::{channel}", "bound", fn, degree=1,
                     note=f"{lo} <= {channel} <= {hi}", params={"channel": channel, "lo": float(lo), "hi": float(hi)})


def linear_relation(target: str, terms: Sequence[tuple[str, float]], const: float = 0.0,
                    diff_target: bool = False, name: str | None = None) -> Invariant:
    """target (or its first difference) minus a weighted sum of channels."""

    def fn(df: pd.DataFrame) -> np.ndarray:
        if target not in df.columns or any(ch not in df.columns for ch, _ in terms):
            return np.full(len(df), np.nan)
        y = df[target].to_numpy(float)
        if diff_target:
            out = np.full(len(df), np.nan)
            base = y[1:] - y[:-1]
            acc = np.full(len(df) - 1, const)
            for ch, w in terms:
                acc = acc + w * df[ch].to_numpy(float)[1:]
            out[1:] = base - acc
            return out
        acc = np.full(len(df), const)
        for ch, w in terms:
            acc = acc + w * df[ch].to_numpy(float)
        return y - acc

    label = name or f"linear::{'d' if diff_target else ''}{target}"
    return Invariant(label, "linear", fn, degree=1,
                     note=f"{'d' if diff_target else ''}{target} = " +
                          " + ".join(f"{w:+.4g}*{c}" for c, w in terms) + f" {const:+.4g}",
                     params={"target": target, "terms": [[c, float(w)] for c, w in terms], "const": float(const),
                             "diff_target": bool(diff_target)})
