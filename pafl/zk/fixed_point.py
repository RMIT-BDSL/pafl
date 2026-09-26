"""Fixed-point form of a mined invariant set, and the integer reference model.

The circuit (zk/lite/circuits/invariant_check.circom) cannot do floating point.
zk/scripts/export_invariants.py uses this module to write
zk/data/invariants_swat_{narrow,wide}.json, and zk/lite/scripts/gen_main.py
bakes those numbers into the circuit. Every mined invariant is affine in the
channels,

    r_j(x_{t-1}, x_t) = J_prev[j] . x_{t-1} + J_cur[j] . x_t + c_j,

so with channel values and coefficients both scaled by S = 2^16 the residual is
an integer, r_hat = J_hat_prev . x_hat_prev + J_hat_cur . x_hat_cur + c_hat, equal
to S^2 r up to rounding, and the check |r| <= eps becomes the range check
|r_hat| <= eps_hat. This module

  * extracts (J, c) with `affine_model` and applies the three guards the ZK plan
    asks for (a probe row where every rule applies; finite-difference noise
    snapped to zero; every channel a rule touches present in `columns`);
  * quantises J, c, eps and records the applicability predicate of each rule
    (a coupling applies only in one of its two steady actuator states and,
    for a steady_only rule such as every mined SWaT coupling, only if the
    state did not change since the previous row; a balance needs the previous
    row);
  * evaluates the same rules in integer arithmetic so the export can be checked
    against `InvariantSet.batch_verdict` before any circuit is written.

Only affine kinds are supported: couplings, balances and linear relations. A
range bound is piecewise and must be left out (include_weak_bounds=False).

Scale and rounding. x_hat = rint(S x), J_hat = round(S J), c_hat = round(S^2 c),
all to the nearest integer with ties to even (numpy rint and Python round
agree). S = 2^16 resolves 1.5e-5 of an engineering unit. The smallest real
coefficient in the SWaT sets is 0.018, which quantises to 1,169, a relative
error of at most 4e-4.

Tolerance and rounding error. eps_hat = round(S^2 eps) + S. Expanding the
products gives a hard bound on the rounding error of the residual:

    |r_hat - S^2 r| <= (S/2) * sum_k (|J_k| + |x_k|) + n_terms/4 + 1/2.

The extra S (1/S = 1.5e-5 in residual units) is a nominal slack. It is not
this bound, and the measured error can exceed it: up to 1.7 S on the simulated
plant (the test data). What keeps rounding from rejecting honest data is the
size of the error relative to eps. A row can change verdict only if its float
residual lies within that error of eps. By the bound, that sliver is under
0.5 % of eps on the simulated plant; on SWaT the export's `checks` block
records a measured maximum of 4.3e-5 of eps. eps is 1.5 times the 99.9th percentile of honest |r|, and a batch is
rejected only when more than 1 % of its rows violate. The exports record zero
violation disagreements on the SWaT calibration half (127,809 cells for the
wide set) and the same verdict on 50 honest and 50 rolled batches. So "no
false rejects from rounding" is measured, not proved. A proof would need a
per-rule slack of at least the bound above.

Integer range. numpy int64 overflows silently, so the reference model is exact
only while |r_hat| < 2^63. The circuit admits a channel value only if
x_hat + 2^31 fits in 32 bits, i.e. -2^31 <= x_hat < 2^31, which is
|x| < 32,768 units (zk/lite/scripts/export_batches.py asserts it). The
committed exports have sum_k |J_hat_k| <= 1.56e6 (balance::LIT101) and
|c_hat| < 2^36, so |r_hat| < 1.56e6 * 2^31 + 2^36 < 2^52 on any admissible
row. That is far inside int64 and far inside the circuit's BN254 scalar field
(p ~ 2^254), so neither the reference model nor the circuit wraps around.

Nothing here touches telemetry values except to run the checks; the export
itself holds coefficients, constants and tolerances only.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from ..attacks.adaptive import affine_model, applicable_rows
from ..invariants.spec import InvariantSet

SCALE_BITS = 16                 # S = 2^16; see "Scale and rounding" above
S_DEFAULT = 1 << SCALE_BITS


def snap_noise(J: np.ndarray, rel: float = 1e-9) -> np.ndarray:
    """Zero every coefficient below `rel` times the largest one in its row.

    `affine_model` recovers J by finite differences, so a channel a rule never
    reads can carry 1e-13 of numerical noise; in fixed point that would become a
    spurious (zero) coefficient and, worse, a spurious dependency in the channel
    map. The cut of 1e-9 sits between finite-difference noise (about 2e-12
    relative on SWaT) and the smallest real coefficient (2.6e-3 of its row's
    largest on SWaT)."""
    J = J.copy()
    for j in range(J.shape[0]):
        m = np.abs(J[j]).max()
        if m > 0:
            J[j, np.abs(J[j]) < rel * m] = 0.0
    return J


def _applicability(inv, report: dict | None) -> dict:
    """The predicate the circuit must replicate for rule `inv`.

    Read from `inv.params` (set by the constructors in pafl.invariants.spec); the
    mining report is the fallback for sets built before that field existed."""
    if inv.kind == "coupling":
        pr = inv.params or {}
        status = pr.get("status"); flow = pr.get("flow")
        if status is None:
            status, flow = inv.name.split("::", 1)[1].split("~", 1)
        entry = next((c for c in (report or {}).get("couplings", [])
                      if c["status"] == status and c["flow"] == flow), None)
        # Fallbacks for old sets: the 0/1 encoding of status_flow_coupling, and
        # steady_only exactly when the miner produced the rule (the miner
        # always builds steady_only couplings; hand-written ones default off).
        off = pr.get("off_value", entry["off_value"] if entry else 0.0)
        on = pr.get("on_value", entry["on_value"] if entry else 1.0)
        steady = pr.get("steady_only", entry is not None)
        rule = "applies when rint(status) is off_value or on_value"
        if steady:
            rule += " and equals rint(status) of the previous row"
        return {"type": "coupling", "status_channel": status, "flow_channel": flow,
                "off_value": float(off), "on_value": float(on), "steady_only": bool(steady), "rule": rule}
    if inv.kind in ("balance", "linear"):
        return {"type": inv.kind, "rule": "applies to every row that has a previous row"}
    return {"type": inv.kind, "rule": "applies to every row"}


def quantise_invariants(inv_set: InvariantSet, probe_df: pd.DataFrame, columns: list[str],
                        scale_bits: int = SCALE_BITS, report: dict | None = None) -> dict:
    """Fixed-point export of `inv_set` over the channel order `columns`.

    probe_df : honest rows on which the affine model is fitted; must contain a
               row where every rule applies (asserted). The export script
               passes the calibration half.
    report   : the miner's report. Consulted only for sets whose couplings
               predate `Invariant.params`, to recover the steady states.
    Returns a JSON-serialisable dict; see the keys written below. Each rule
    keeps its float values next to the integers, so the circuit's constants
    can be audited against the float model. Raises ValueError if a rule
    touches a channel outside `columns` or has no calibrated tolerance.
    """
    S = 1 << scale_bits
    probe_df = probe_df.copy()
    probe_df[columns] = probe_df[columns].astype(float)   # finite differences need float cells (actuators are ints)
    ok = applicable_rows(inv_set, probe_df).all(axis=1)
    if not ok.any():
        raise ValueError("no probe row on which every invariant applies; the intercept cannot be recovered")
    J, c = affine_model(inv_set, probe_df, columns)
    J = snap_noise(J)
    n_col = len(columns)
    invariants = []
    touched: set[str] = set()
    for j, inv in enumerate(inv_set):
        prev = {columns[d]: float(J[j, d]) for d in range(n_col) if J[j, d] != 0.0}
        cur = {columns[d]: float(J[j, n_col + d]) for d in range(n_col) if J[j, n_col + d] != 0.0}
        app = _applicability(inv, report)
        named = set(prev) | set(cur) | ({app["status_channel"], app["flow_channel"]} if app["type"] == "coupling" else set())
        missing = [ch for ch in named if ch not in columns]
        if missing:
            raise ValueError(f"{inv.name} touches channels absent from the column list: {missing}")
        touched |= named
        if inv.eps is None:
            raise ValueError(f"{inv.name} has no tolerance; calibrate the set first")
        invariants.append({
            "name": inv.name, "kind": inv.kind, "note": inv.note,
            # + S: nominal rounding slack, not a bound (module docstring)
            "eps": float(inv.eps), "eps_hat": int(round(inv.eps * S * S)) + S,
            "c": float(c[j]), "c_hat": int(round(float(c[j]) * S * S)),
            "coef_prev": {ch: {"float": v, "int": int(round(v * S))} for ch, v in prev.items()},
            "coef_cur": {ch: {"float": v, "int": int(round(v * S))} for ch, v in cur.items()},
            "applicability": app,
        })
    return {
        "scale_bits": scale_bits, "S": S,
        "quantisation": {"x_hat": "round(S * x)", "J_hat": "round(S * J)", "c_hat": "round(S^2 * c)",
                         "eps_hat": "round(S^2 * eps) + S  (one unit of slack for rounding)",
                         "residual": "r_hat = sum_prev J_hat * x_hat[t-1] + sum_cur J_hat * x_hat[t] + c_hat ~ S^2 * r",
                         "check": "applicable(t) implies |r_hat| <= eps_hat",
                         "sampling": "indices are drawn from 1..N-1; row 0 is never checked because every check opens the pair (x[t-1], x[t])"},
        "columns": list(columns),
        "channel_index": {ch: i for i, ch in enumerate(columns)},
        "channels_touched": sorted(touched, key=columns.index),
        "n_invariants": len(invariants),
        "invariants": invariants,
    }


# ------------------------------------------------------------------ integer reference model
def quantise_rows(df: pd.DataFrame, columns: list[str], S: int) -> np.ndarray:
    """x_hat = round(S * x) as int64, shape (n_rows, n_col). No range check:
    values beyond the circuit's 32-bit window are the caller's to reject."""
    return np.rint(df[columns].to_numpy(float) * S).astype(np.int64)


def integer_residuals(X_hat: np.ndarray, q: dict) -> np.ndarray:
    """r_hat for every row (row 0 is 0 and never applicable) and every invariant."""
    idx = q["channel_index"]
    n, _ = X_hat.shape
    R = np.zeros((n, q["n_invariants"]), dtype=np.int64)
    for j, inv in enumerate(q["invariants"]):
        acc = np.full(n - 1, inv["c_hat"], dtype=np.int64)
        for ch, v in inv["coef_prev"].items():
            acc += np.int64(v["int"]) * X_hat[:-1, idx[ch]]
        for ch, v in inv["coef_cur"].items():
            acc += np.int64(v["int"]) * X_hat[1:, idx[ch]]
        R[1:, j] = acc
    return R


def integer_applicable(X_hat: np.ndarray, q: dict) -> np.ndarray:
    """The applicability predicate evaluated on quantised rows; row 0 never applies.

    rint(x_hat / S) recovers an integral actuator code exactly, so this matches
    the float model's rint(status) on every row with an integral code."""
    idx, S = q["channel_index"], q["S"]
    n = X_hat.shape[0]
    A = np.ones((n, q["n_invariants"]), dtype=bool)
    A[0, :] = False
    for j, inv in enumerate(q["invariants"]):
        app = inv["applicability"]
        if app["type"] == "coupling":
            st = np.rint(X_hat[:, idx[app["status_channel"]]] / S)
            steady = (st == app["off_value"]) | (st == app["on_value"])
            A[:, j] &= steady
            if app.get("steady_only", True):
                A[1:, j] &= st[1:] == st[:-1]
    return A


def integer_violations(X_hat: np.ndarray, q: dict) -> np.ndarray:
    """Boolean (n_rows, n_invariants): applicable and |r_hat| > eps_hat."""
    R = integer_residuals(X_hat, q)
    eps = np.array([inv["eps_hat"] for inv in q["invariants"]], dtype=np.int64)
    return (np.abs(R) > eps[None, :]) & integer_applicable(X_hat, q)


def integer_verdict(X_hat: np.ndarray, q: dict, max_violating_frac: float = 0.01) -> dict:
    """The admission decision on quantised rows, with the float model's rule
    and 1 % threshold (`InvariantSet.batch_verdict`) and the same denominator:
    every row, row 0 included."""
    v = integer_violations(X_hat, q)
    frac = float(v.any(axis=1).mean()) if len(X_hat) else 0.0
    return {"violating_fraction": frac, "admitted": bool(frac <= max_violating_frac),
            "per_invariant_violating_fraction": {inv["name"]: float(x) for inv, x in zip(q["invariants"], v.mean(axis=0))}}


def fidelity(inv_set: InvariantSet, df: pd.DataFrame, columns: list[str], q: dict) -> dict:
    """How far the integer model is from the float one on `df`.

    Residual error is reported in units of each rule's tolerance (the quantity
    the range check compares against); applicability and violation disagreements
    are counted per cell; the batch verdicts are compared as decisions.
    """
    S = q["S"]
    X_hat = quantise_rows(df, columns, S)
    # Row 0 is never sampled by the protocol (indices run over 1..N-1 because every
    # check opens the pair x[i-1], x[i]), so the comparison starts at row 1.
    R_float = inv_set.residuals(df)[1:]
    A_float = np.isfinite(R_float)
    R_int = (integer_residuals(X_hat, q) / (S * S))[1:]
    A_int = integer_applicable(X_hat, q)[1:]
    eps = np.array([inv["eps"] for inv in q["invariants"]])
    both = A_float & A_int
    err = np.abs(R_int - np.nan_to_num(R_float))
    err_over_eps = (err / eps[None, :])[both]
    V_float = inv_set.violations(df)[1:]
    V_int = integer_violations(X_hat, q)[1:]
    return {
        "rows": int(len(df)),
        "residual_error_max_over_eps": float(err_over_eps.max()) if err_over_eps.size else 0.0,
        "residual_error_mean_over_eps": float(err_over_eps.mean()) if err_over_eps.size else 0.0,
        "applicability_disagreements": int((A_float != A_int).sum()),
        "violation_disagreements": int((V_float != V_int).sum()),
        "cells": int(A_float.size),
        "float_violating_fraction": float(V_float.any(axis=1).mean()),
        "integer_violating_fraction": float(V_int.any(axis=1).mean()),
    }
