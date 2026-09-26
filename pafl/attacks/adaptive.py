"""The adaptive attacker: project a fabricated batch back onto the physics.

`project_batch` is the paper's physics-aware attacker. Given the mined
invariants and their tolerances, it moves a poisoned batch the least it can
so that the batch passes the check. It solves

    min_X  ||X - X_fabricated||   subject to   |residual_j(X)| <= eps_j  for all j

and submits the projection instead. pafl/fl/variants.py builds the federations
the paper compares. Mode `fabricated` is the paper's "naive attack": the
Recipe A/B or replay batch submitted as is. Mode `projected` is the
"physics-aware attack": the same batch after `project_batch`, admitted
regardless of the gate. Mode `gated` is the same projected batch with the
gate enforced. Comparing them measures how much poisoning damage survives the
projection.

Two properties make this cheap, and both come from a design choice made for
the circuit rather than for the attacker. Every invariant is affine in the
channels of two consecutive rows. Each constraint is therefore a slab between
parallel hyperplanes, and the feasible set is convex. The paper describes the
solve as alternating projections. The code uses the active-set minimum-norm
correction documented on `project_batch`. Being affine also means the Jacobian
is constant, so it is recovered once by finite-difference probing instead of
once per row. The module checks that the Jacobian really is constant and warns
loudly when it is not, because a non-linear invariant would silently make the
attacker look weaker than it is. The same affine model is what
pafl/zk/fixed_point.py exports to the circuit.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

from ..invariants.spec import InvariantSet


class NonLinearInvariantWarning(RuntimeWarning):
    """Raised as a warning when the constant-Jacobian assumption fails."""


def _as_float(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    out = df.copy()
    for c in columns:
        out[c] = out[c].astype(float)
    return out


def _jacobian_at(inv_set: InvariantSet, df: pd.DataFrame, columns: list[str],
                 row: int, delta: float = 1e-4) -> np.ndarray:
    """d residual_j / d channel, for the previous row and the current row.

    Shape (n_invariants, 2 * n_columns). Invariants in this project touch at
    most two consecutive rows. Forward differences with step `delta` = 1e-4
    are exact for an affine residual up to float rounding (about 1e-12
    relative, which `zk.fixed_point.snap_noise` removes). The step is small
    enough that rint() of an actuator state cannot flip, so probing never
    changes which rules apply.
    """
    n_col = len(columns)
    lo = max(row - 1, 0)
    window = df.iloc[lo:row + 1]
    base = np.nan_to_num(inv_set.residuals(window)[-1])
    J = np.zeros((len(inv_set), 2 * n_col))
    for blk, r in enumerate((row - 1, row)):
        if r < 0:
            continue
        local = r - lo
        for c, col in enumerate(columns):
            probe = window.copy()
            probe.iat[local, probe.columns.get_loc(col)] += delta
            pert = np.nan_to_num(inv_set.residuals(probe)[-1])
            J[:, blk * n_col + c] = (pert - base) / delta
    return J


def applicable_rows(inv_set: InvariantSet, df: pd.DataFrame) -> np.ndarray:
    """Boolean (n_rows, n_invariants): where each rule applies to the row.

    A coupling does not apply while the actuator is in a transition state or on
    the row after a switch; a balance does not apply on row 0. Those cells carry
    a NaN residual, and the projection must not treat them as constraints.
    """
    return np.isfinite(inv_set.residuals(df))


def _probe_rows(inv_set: InvariantSet, df: pd.DataFrame) -> tuple[int, int, int]:
    """Three rows (near 1/3, 1/2, 2/3 of the batch) on which every rule applies.

    If no such row exists the fallback rows are arbitrary, and an inapplicable
    rule then contributes a zero Jacobian row and a wrong intercept. Callers
    who need the model to be right, such as the fixed-point export, check for
    a fully applicable row first."""
    ok = applicable_rows(inv_set, df).all(axis=1)
    ok[0] = False
    idx = np.where(ok)[0]
    n = len(df)
    if idx.size == 0:
        return max(1, n // 3), max(1, n // 2), max(2, 2 * n // 3)
    pick = lambda target: int(idx[np.argmin(np.abs(idx - target))])
    return pick(n // 3), pick(n // 2), pick(2 * n // 3)


def constant_jacobian(inv_set: InvariantSet, df: pd.DataFrame, columns: list[str],
                      atol: float = 1e-4) -> np.ndarray:
    """Compute the Jacobian once and verify it does not depend on the row.

    The comparison is made at two rows a third of the batch apart. The
    tolerances (atol 1e-4 of the largest coefficient, rtol 1e-3) sit far above
    finite-difference noise (about 1e-12 relative), so only a Jacobian that
    really depends on the row trips the warning. A range bound, which is
    piecewise, would trip it."""
    import warnings

    r1, _, r2 = _probe_rows(inv_set, df)
    J1 = _jacobian_at(inv_set, df, columns, r1)
    J2 = _jacobian_at(inv_set, df, columns, r2)
    scale = max(np.abs(J1).max(), 1e-12)
    if not np.allclose(J1, J2, atol=atol * scale, rtol=1e-3):
        warnings.warn(
            "invariant residuals are not linear in the channels; the projection "
            "is approximate and understates what an adaptive attacker can do",
            NonLinearInvariantWarning, stacklevel=2)
    return J1


def affine_model(inv_set: InvariantSet, df: pd.DataFrame, columns: list[str]
                 ) -> tuple[np.ndarray, np.ndarray]:
    """Write the residuals as r(X) = J . [X[t-1]; X[t]] + c.

    Every invariant here is affine, so once J and c are known the residuals of
    the whole batch are one matrix product. That removes the dataframe from the
    inner loop and turns the projection into a few hundred cheap numpy steps.
    The intercept c is read off at the middle probe row.
    """
    J = constant_jacobian(inv_set, df, columns)
    X = df[columns].to_numpy(float)
    _, t, _ = _probe_rows(inv_set, df)
    r_t = np.nan_to_num(inv_set.residuals(df.iloc[t - 1:t + 1])[-1])
    c = r_t - J @ np.concatenate([X[t - 1], X[t]])
    return J, c


def _residuals_affine(X: np.ndarray, J: np.ndarray, c: np.ndarray) -> np.ndarray:
    """Residual matrix (n_rows, n_inv) from the affine model. Row 0 is zero."""
    n_col = X.shape[1]
    prev = J[:, :n_col] @ X[:-1].T          # (n_inv, n_rows-1)
    cur = J[:, n_col:] @ X[1:].T
    R = np.zeros((X.shape[0], J.shape[0]))
    R[1:] = (prev + cur + c[:, None]).T
    return R


def _build_constraint_matrix(rows: np.ndarray, invs: np.ndarray, J: np.ndarray,
                             n_rows: int, n_col: int, col_mask: np.ndarray):
    """Sparse matrix A with one row per active constraint.

    Variables are the flattened batch, index = row * n_col + channel. Each
    constraint touches the previous row and the current row, so A has at most
    2 * n_col non-zeros per row and is banded.
    """
    from scipy import sparse

    keep = np.where(col_mask)[0]
    n_act = rows.size
    data, ri, ci = [], [], []
    for blk, offset in ((0, -1), (1, 0)):
        block = J[invs][:, blk * n_col:(blk + 1) * n_col][:, keep]      # (n_act, n_free)
        tgt_rows = rows + offset
        ok = tgt_rows >= 0
        for c_local, c_global in enumerate(keep):
            vals = block[:, c_local]
            nz = np.where((vals != 0) & ok)[0]
            if nz.size == 0:
                continue
            data.append(vals[nz])
            ri.append(nz)
            ci.append(tgt_rows[nz] * n_col + c_global)
    if not data:
        return sparse.csr_matrix((n_act, n_rows * n_col))
    return sparse.csr_matrix(
        (np.concatenate(data), (np.concatenate(ri), np.concatenate(ci))),
        shape=(n_act, n_rows * n_col))


def project_batch(df: pd.DataFrame, inv_set: InvariantSet, columns: list[str],
                  n_outer: int = 30, step_damping: float = 1.0,
                  target_violating: float = 0.0, protect: tuple[str, ...] = (),
                  margin: float = 0.95, verbose: bool = False) -> pd.DataFrame:
    """Move the batch as little as possible while satisfying every invariant.

    The attacker solves

        min_X  ||X - X0||^2   subject to   |r_j(X_t)| <= eps_j  for every t, j

    Because every invariant is affine, each constraint is a slab and the problem
    is a convex quadratic program. It is solved here by an active-set loop. At
    each pass the violating constraints are collected, the smallest move that
    lands every one of them just inside its tolerance is found in closed form as
    dX = A^T (A A^T)^-1 gap, and the active set is then recomputed. Constraints
    are sparse and banded -- each touches two consecutive rows -- so the normal
    equations stay cheap even for a batch of thousands of rows. Each pass is a
    minimum-norm step, so the result is a nearby feasible point, not a
    certified optimum of the QP.

    Settings in the paper runs (pafl/fl/variants.py): `protect` = every
    discrete channel, `target_violating` = 0.005, everything else at its
    default. The loop stops as soon as at most `target_violating` of rows
    violate, so 0.005 leaves half of the 1 % admission threshold as margin.
    `margin` = 0.95 aims each repaired residual at 95 % of its tolerance
    rather than exactly at the edge. If `n_outer` passes run out first,
    the batch is returned as it stands and may still fail the check. The
    caller re-checks it and records `admitted_after`. A stronger attacker sets
    `target_violating` = 0 or leaves the actuators unprotected. The second
    option is cheaper (tests/test_attacks.py) but writes fractional pump
    states.

    A note on what did not work, because it is instructive. Projecting each
    violating row independently over-corrects: an invariant at row t and the
    same invariant at row t+1 both touch row t. And a fixed-penalty gradient
    descent lowers the total squared excess while raising the *number* of
    violating rows, which reduces its own objective and fails the admission rule.
    Only solving for feasibility across the coupled constraints gives the
    attacker what it actually needs.

    `protect` names channels the attacker leaves alone, normally the discrete
    actuator states, since fractional pump states would give the fabrication away
    by other means. Protecting channels shrinks the feasible set and raises the
    cost, and that cost is one of the things worth measuring. With actuators
    unprotected, applicability is still taken from the input batch and is not
    recomputed as states move; the caller's final `batch_verdict` is the
    ground truth. Deterministic: no random numbers are drawn.
    """
    from scipy.sparse import eye as speye
    from scipy.sparse.linalg import cg

    work = _as_float(df, columns)
    free = [x for x in columns if x not in protect]
    if not free:
        return work

    J, c = affine_model(inv_set, work, columns)
    n_col = len(columns)
    n_rows = len(work)
    eps = np.array([i.eps if i.eps is not None else np.inf for i in inv_set])
    finite = np.isfinite(eps)
    col_mask = np.zeros(n_col, dtype=bool)
    col_mask[[columns.index(x) for x in free]] = True

    X0 = work[columns].to_numpy(float)
    X = X0.copy()
    sticky = np.zeros((n_rows, len(inv_set)), dtype=bool)
    # Rules that do not apply to a row (transition states, the row after a
    # switch, row 0 of a difference) are not constraints. The discrete channels
    # are normally protected, so applicability is fixed for the whole solve.
    applicable = applicable_rows(inv_set, work)

    for outer in range(n_outer):
        R = _residuals_affine(X, J, c)
        excess = np.abs(R) - eps[None, :]
        act = (excess > 0) & finite[None, :] & applicable
        act[0, :] = False
        viol = float(act.any(axis=1).mean())
        if verbose:
            print(f"  outer {outer:2d} violating {viol:.4f} active {int(act.sum())} "
                  f"shift {np.abs(X - X0).mean():.5f}")
        if viol <= target_violating:
            break

        # A constraint stays in the working set once it has been violated. Letting
        # constraints leave makes the active set oscillate: repairing row t pushes
        # row t+1 out, repairing t+1 pushes t back out, and the violation count
        # stalls around a fixed point instead of falling. Constraints already
        # inside tolerance contribute a zero gap, so they act as anchors that
        # stop the solver undoing its own work.
        sticky |= act
        rows, invs = np.where(sticky)
        A = _build_constraint_matrix(rows, invs, J, n_rows, n_col, col_mask)
        r_act = R[rows, invs]
        gap = np.clip(r_act, -eps[invs] * margin, eps[invs] * margin) - r_act

        # min ||dX|| s.t. A dX = gap  ->  dX = A^T (A A^T)^-1 gap
        # The 1e-10 ridge keeps A A^T positive definite when constraints are
        # linearly dependent or a row of A is empty (all its channels
        # protected). CG's convergence flag `info` is not checked; an
        # unconverged solve shows up as a batch that is still violating.
        AAt = (A @ A.T).tocsc() + 1e-10 * speye(A.shape[0], format="csc")
        lam, info = cg(AAt, gap, rtol=1e-9, maxiter=2000)
        dX = (A.T @ lam).reshape(n_rows, n_col)
        dX[:, ~col_mask] = 0.0

        # damped step keeps the active set from thrashing between iterations
        X = X + step_damping * dX

    work[columns] = X
    return work


def projection_cost(original: pd.DataFrame, projected: pd.DataFrame,
                    columns: list[str]) -> dict:
    """How far the attacker had to move, in units of each channel's own scale.

    Sigma is each channel's standard deviation in the original batch. A row
    counts as moved if any channel shifted by more than 1e-6 sigma. These are
    the `projection` records in the adaptive result files."""
    a = original[columns].to_numpy(float)
    b = projected[columns].to_numpy(float)
    scale = a.std(axis=0) + 1e-9
    d = (b - a) / scale
    return {
        "mean_abs_shift_sigma": float(np.abs(d).mean()),
        "max_abs_shift_sigma": float(np.abs(d).max()),
        "frac_rows_moved": float((np.abs(d) > 1e-6).any(axis=1).mean()),
        "frobenius_shift": float(np.linalg.norm(b - a)),
    }
