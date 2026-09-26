"""Fabrications must do what their metadata claims, and the adaptive projection
must actually reach feasibility.

All on the simulated plant (2,000 rows, seed 1) with its exact invariants and
no range bounds, so the tests need no licensed data. Recipe B and the
update-space attacks are tested in tests/test_week2.py.
"""
import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.attacks.adaptive import project_batch, projection_cost
from pafl.attacks.recipe_a import FABRICATIONS, fabricate
from pafl.data.loaders import feature_columns
from pafl.data.synthetic import simulate
from pafl.invariants.plants import synthetic_invariants


@pytest.fixture(scope="module")
def setup():
    clean = simulate(2000, seed=1)
    inv = synthetic_invariants(clean, include_weak_bounds=False).calibrate(clean)
    return clean, inv, feature_columns(clean)


@pytest.mark.parametrize("kind", ["channel_roll", "within_regime_permutation", "regime_splicing"])
def test_marginal_preserving_claims_are_true(setup, kind):
    """If a transform claims to preserve marginals, check it, because that claim
    is what the paper argues from."""
    clean, _, cols = setup
    fab = fabricate(clean, kind, seed=3)
    assert "per-channel marginal" in FABRICATIONS[kind].preserves
    for c in cols:
        assert np.allclose(np.sort(clean[c].to_numpy(float)), np.sort(fab[c].to_numpy(float))), c


def test_conservation_scaling_does_not_claim_marginals():
    """The honest negative case: this one changes the flow distribution and the
    metadata must not pretend otherwise."""
    assert "per-channel marginal" not in FABRICATIONS["conservation_scaling"].preserves


def test_flow_channels_found_under_every_naming_scheme():
    """conservation_scaling must find the flows on every record the paper uses.

    Selecting names that start with F found none on WADI or HAI, so the
    fabrication returned the honest batch unchanged there.
    """
    from pafl.attacks.recipe_a import is_flow_channel
    flows = ["FIT101", "FIT601", "F_PU1", "F_V2", "1_FIT_001_PV", "2_FIC_101_PV",
             "P1_FT01", "P1_FT01Z", "P3_FIT01"]
    not_flows = ["LIT101", "DPIT301", "L_T1", "P_J280", "S_PU1", "DEMAND", "2_FIC_101_CO",
                 "2_FIC_101_SP", "2_FQ_101_PV", "1_LT_001_PV", "2_P_003_SPEED", "P1_FCV01D", "P4_HT_FD"]
    assert all(is_flow_channel(c) for c in flows), [c for c in flows if not is_flow_channel(c)]
    assert not any(is_flow_channel(c) for c in not_flows), [c for c in not_flows if is_flow_channel(c)]


@pytest.mark.parametrize("kind", ["channel_roll", "within_regime_permutation", "conservation_scaling"])
def test_fabrication_breaks_the_physics(setup, kind):
    """Each Recipe A transform the paper uses must be rejected by the gate, and
    by a clear margin (over 5 % violating rows against the 1 % rule)."""
    clean, inv, _ = setup
    fab = fabricate(clean, kind, seed=3)
    assert inv.batch_verdict(fab)["violating_fraction"] > 0.05
    assert not inv.batch_verdict(fab)["admitted"]


def test_regime_splicing_evades_a_fraction_threshold(setup):
    """A documented limitation, kept as a test so it cannot regress silently.

    Splicing breaks the physics only at the join points, so with few segments the
    violating fraction stays under a percentage-based admission rule. The paper
    must say this rather than let a reviewer find it. regime_splicing is not one
    of the paper's attacks for that reason.
    """
    clean, inv, _ = setup
    fab = fabricate(clean, "regime_splicing", seed=3, n_segments=12)
    assert inv.batch_verdict(fab)["violating_fraction"] < 0.01


@pytest.mark.parametrize("kind", ["channel_roll", "conservation_scaling"])
def test_adaptive_projection_reaches_feasibility(setup, kind):
    """The physics-aware attacker, at the paper's target_violating of 0.005,
    turns a rejected batch into an admitted one."""
    clean, inv, cols = setup
    fab = fabricate(clean, kind, seed=3)
    proj = project_batch(fab, inv, cols, target_violating=0.005)
    assert inv.batch_verdict(proj)["admitted"]


def test_protecting_actuators_costs_the_attacker_more(setup):
    """Denying the attacker the discrete channels should raise the distance it
    must travel. If it does not, the protected variant is not worth reporting."""
    clean, inv, cols = setup
    fab = fabricate(clean, "channel_roll", seed=3)
    prot = tuple(c for c in cols if c.startswith("S_"))
    free_cost = projection_cost(fab, project_batch(fab, inv, cols, target_violating=0.005),
                                cols)["mean_abs_shift_sigma"]
    prot_cost = projection_cost(fab, project_batch(fab, inv, cols, protect=prot,
                                                   target_violating=0.005),
                                cols)["mean_abs_shift_sigma"]
    assert prot_cost > free_cost


def test_splice_only_is_the_identity():
    """The replay attacker's "fabrication" returns an equal copy, never the input
    object, so later in-place edits cannot reach the honest frame."""
    import numpy as np
    from pafl.data.synthetic import simulate
    from pafl.attacks.recipe_a import fabricate, FABRICATIONS
    df = simulate(500, seed=3)
    out = fabricate(df, "splice_only", seed=0)
    assert out is not df and out.equals(df)
    assert "splice_only" in FABRICATIONS
