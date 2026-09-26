"""The invariant layer. These tests pin down the two things most likely to be
wrong in a hurry: time alignment, and whether epsilon is doing its job.

All of them run on the simulated plant (or on small hand-made frames), so they
need no dataset. The simulator's physics are exact, which is what lets a test
demand near-zero residuals and exact recovered coefficients."""
import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.data.synthetic import simulate, default_attacks
from pafl.invariants.plants import synthetic_invariants
from pafl.invariants.mine import build_invariant_set, mine_linear_balances


@pytest.fixture(scope="module")
def clean():
    return simulate(4000, seed=1)


def test_mass_balance_is_exact_on_clean_data(clean):
    """The only residual on honest data should be sensor noise.

    The plant writes the level after the flows in the same row have acted, so
    the balance uses flows at index t. Getting this wrong does not look like a
    bug; it looks like extra noise, which is far worse.
    """
    inv = synthetic_invariants(clean, include_weak_bounds=False)
    R = inv.residuals(clean)
    for j, i in enumerate(inv):
        if not i.name.startswith("balance"):
            continue
        r = R[1:, j]
        assert abs(np.mean(r)) < 1e-3, f"{i.name} is biased: physics or alignment is wrong"
        assert np.std(r) < 0.02, f"{i.name} residual too large for sensor noise alone"


def test_wrong_time_alignment_is_detectable(clean):
    """A one-step misalignment must inflate the residual, so the test above bites."""
    meta = clean.attrs["plant"]
    L = clean["L_T1"].to_numpy(float)
    fi = clean["F_PU1"].to_numpy(float)
    fo = clean["F_PU2"].to_numpy(float)
    a, dt = meta["area"][0], meta["dt"]
    right = (L[1:] - L[:-1] - dt * (fi[1:] - fo[1:]) / a).std()
    wrong = (L[1:] - L[:-1] - dt * (fi[:-1] - fo[:-1]) / a).std()
    assert wrong > 3 * right


def test_honest_data_is_admitted(clean):
    """In-sample: calibrated and checked on the same run. It shows the admission
    rule is not too tight by construction; the out-of-sample false-rejection
    rate is measured by scripts/separation.py."""
    inv = synthetic_invariants(clean, include_weak_bounds=False).calibrate(clean)
    v = inv.batch_verdict(clean)
    assert v["admitted"]
    assert v["violating_fraction"] < 0.01


def test_real_attacks_are_flagged():
    """Invariants must also catch genuine attacks on the plant, or they are not
    measuring physics."""
    calib = simulate(4000, seed=2)
    inv = synthetic_invariants(calib, include_weak_bounds=False).calibrate(calib)
    atk = simulate(4000, seed=2, attacks=default_attacks(4000, seed=2, n=8))
    assert inv.batch_verdict(atk)["violating_fraction"] > inv.batch_verdict(calib)["violating_fraction"]


def test_miner_recovers_known_physics(clean):
    """The miner should rediscover 1/area coefficients it was never told, to
    within 5 %."""
    rel = {r.target: r for r in mine_linear_balances(clean)}
    areas = clean.attrs["plant"]["area"]
    for i, a in enumerate(areas):
        r = rel[f"L_T{i+1}"]
        terms = dict(r.terms)
        assert r.r2 > 0.98, f"tank {i+1}: mined relation explains too little"
        assert abs(terms[f"F_PU{i+1}"] - 1 / a) < 0.05 / a
        assert abs(terms[f"F_PU{i+2}"] + 1 / a) < 0.05 / a


def test_circuit_cost_scales_with_k(clean):
    """The pre-build estimate is linear in the number of sampled rows k."""
    inv = synthetic_invariants(clean).calibrate(clean)
    c1 = inv.circuit_cost(32)["constraints_total"]
    c2 = inv.circuit_cost(64)["constraints_total"]
    assert c2 == 2 * c1


# ----------------------------------------------------------------------------
# coupling with a non-binary actuator encoding (SWaT: 1 = off, 2 = on, 0 = moving)
# ----------------------------------------------------------------------------
def test_coupling_handles_swat_encoding_and_transitions():
    import numpy as np
    import pandas as pd
    from pafl.invariants.spec import status_flow_coupling

    S = np.array([1, 1, 2, 2, 2, 0, 1, 1, 2], float)
    F = np.array([0, 0, 2.5, 2.5, 2.5, 1.2, 0.9, 0, 2.5], float)
    df = pd.DataFrame({"P101": S, "FIT201": F})
    inv = status_flow_coupling("P101", "FIT201", 2.5, off_value=1.0, on_value=2.0)
    r = inv.residual(df)
    assert np.allclose(r[[0, 1, 2, 3, 4, 7, 8]], 0.0)       # steady rows are exact
    assert np.isnan(r[5])                                    # 0 = transition: not applicable
    assert abs(r[6] - 0.9) < 1e-9                            # lag row violates without steady_only

    inv2 = status_flow_coupling("P101", "FIT201", 2.5, off_value=1.0, on_value=2.0,
                                steady_only=True)
    r2 = inv2.residual(df)
    assert np.isnan(r2[0]) and np.isnan(r2[2]) and np.isnan(r2[6]) and np.isnan(r2[8])
    assert np.allclose(r2[[1, 3, 4, 7]], 0.0)

    # the default 0 = off, 1 = on encoding (BATADAL, the simulator): residual = F - S * nominal
    inv0 = status_flow_coupling("S", "F", 2.0)
    d0 = pd.DataFrame({"S": [0, 1, 1], "F": [0.0, 2.0, 1.5]})
    assert np.allclose(inv0.residual(d0), [0.0, 0.0, -0.5])


def test_coupling_stays_affine_for_the_projection():
    """A probe perturbation on the status must not flip the state, and the
    Jacobian must be the same constant on every applicable row."""
    import numpy as np
    import pandas as pd
    from pafl.invariants.spec import status_flow_coupling
    inv = status_flow_coupling("P", "F", 3.0, off_value=1.0, on_value=2.0)
    df = pd.DataFrame({"P": [1.0, 2.0], "F": [0.0, 3.0]})
    base = inv.residual(df)
    dS = df.copy(); dS["P"] += 1e-4
    dF = df.copy(); dF["F"] += 1e-4
    assert np.allclose((inv.residual(dS) - base) / 1e-4, -3.0)
    assert np.allclose((inv.residual(dF) - base) / 1e-4, 1.0)
