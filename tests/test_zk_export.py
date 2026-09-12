"""The fixed-point invariant model must agree with the float one (zk/PLAN.md, step 3).

Run on the simulated plant, whose invariants are exact and whose data are free
to ship, so the test needs no licensed record."""
import numpy as np

from pafl.data.loaders import feature_columns
from pafl.data.synthetic import simulate
from pafl.invariants.plants import synthetic_invariants
from pafl.zk.fixed_point import fidelity, integer_verdict, quantise_invariants, quantise_rows


def _setup():
    calib = simulate(6000, seed=12345)
    inv = synthetic_invariants(calib, include_weak_bounds=False).calibrate(calib)
    cols = feature_columns(calib)
    q = quantise_invariants(inv, calib, cols)
    return inv, cols, q


def test_export_structure_and_channel_guard():
    inv, cols, q = _setup()
    assert q["n_invariants"] == len(inv) and q["S"] == 2 ** 16
    for e in q["invariants"]:
        assert e["eps_hat"] > q["S"] and set(e["coef_prev"]) | set(e["coef_cur"]) <= set(cols)
        assert e["applicability"]["type"] in ("coupling", "balance", "linear")
    assert set(q["channels_touched"]) <= set(cols)


def test_quantised_residual_fidelity():
    inv, cols, q = _setup()
    df = simulate(4000, seed=7)
    f = fidelity(inv, df, cols, q)
    assert f["applicability_disagreements"] == 0
    assert f["residual_error_max_over_eps"] < 0.05      # rounding error is a small fraction of any tolerance
    assert f["violation_disagreements"] == 0


def test_admission_decision_parity_on_honest_and_rolled_batches():
    from pafl.attacks.recipe_a import fabricate
    inv, cols, q = _setup()
    rs = np.random.default_rng(1)
    pool = simulate(30_000, seed=99)
    agree = total = 0
    for b in range(20):
        i = int(rs.integers(1, len(pool) - 1000))
        batch = pool.iloc[i:i + 1000].reset_index(drop=True)
        for df in (batch, fabricate(batch, "channel_roll", seed=b, shift=7)):
            vf = inv.batch_verdict(df)["admitted"]
            vi = integer_verdict(quantise_rows(df, cols, q["S"]), q)["admitted"]
            agree += int(vf == vi); total += 1
    assert agree == total
