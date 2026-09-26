"""Federated pieces: defences behave as advertised, a run is resumable, and the
five federations of fl.variants are built consistently (the projected attacker
keeps the naive one's oversampling; the gate's counts add up)."""
import sys
from pathlib import Path
import numpy as np
import pytest
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pafl.fl.defences import DEFENCES, aggregate, acceptance_mask
from pafl.fl.models import build_model, get_flat_params, set_flat_params, n_params
from pafl.fl.scenario import ScenarioConfig, build_synthetic_scenario
from pafl.fl.train import FLConfig, run_federation


def test_flat_param_roundtrip():
    m = build_model("window_ae", 11, 10)
    flat = get_flat_params(m).clone()
    set_flat_params(m, torch.zeros_like(flat))
    assert float(get_flat_params(m).abs().sum()) == 0.0
    set_flat_params(m, flat)
    assert torch.allclose(get_flat_params(m), flat)


@pytest.mark.parametrize("name", list(DEFENCES))
def test_defences_return_the_right_shape(name):
    u = torch.randn(8, 40)
    # without a server update FLTrust falls back to FedAvg, so give it one
    kw = {"server_update": u[1:].mean(0)} if name == "fltrust" else {}
    assert aggregate(name, u, n_malicious=2, **kw).shape == (40,)


def test_selective_defences_reject_a_gross_outlier():
    u = torch.randn(10, 40)
    u[0] *= 25                              # far outside the others' cloud
    for name in ("krum", "trimmed_mean"):
        assert not bool(acceptance_mask(name, u, n_malicious=1)[0])


def test_fedavg_includes_everyone():
    u = torch.randn(10, 40)
    assert bool(acceptance_mask("fedavg", u).all())


def test_scenario_marks_malicious_clients():
    sc = build_synthetic_scenario(ScenarioConfig(n_clients=5, malicious_fraction=0.4,
                                                 steps_per_client=800, seed=0))
    assert sum(c.is_malicious for c in sc["clients"]) == 2
    assert all(c.fabrication for c in sc["clients"] if c.is_malicious)


def test_federation_runs_and_is_resumable(tmp_path):
    sc = build_synthetic_scenario(ScenarioConfig(n_clients=3, malicious_fraction=0.0,
                                                 steps_per_client=900, val_steps=500,
                                                 test_steps=900, seed=0))
    ck = tmp_path / "ck.pkl"
    cfg = FLConfig(rounds=2, local_epochs=1, log_every=10_000)
    a = run_federation(sc["clients"], sc["eval_sets"], cfg, root_data=sc["root_data"],
                       ckpt_path=ck)
    assert ck.exists()
    assert 0.0 <= a["results"]["test"]["f1"] <= 1.0
    # same checkpoint, more rounds: rounds 0-1 are loaded, only 2-3 are trained
    cfg2 = FLConfig(rounds=4, local_epochs=1, log_every=10_000)
    b = run_federation(sc["clients"], sc["eval_sets"], cfg2, root_data=sc["root_data"],
                       ckpt_path=ck)
    assert len(b["history"]) == 4          # resumed rather than restarted


def test_threshold_is_never_taken_from_the_test_set():
    """Calibrating on test data inflates every number that follows. The API makes
    that hard on purpose, and this test says so."""
    sc = build_synthetic_scenario(ScenarioConfig(n_clients=2, malicious_fraction=0.0,
                                                 steps_per_client=700, val_steps=400,
                                                 test_steps=700, seed=0))
    bad = {k: v for k, v in sc["eval_sets"].items() if k != "clean_val"}
    with pytest.raises(ValueError):
        run_federation(sc["clients"], bad, FLConfig(rounds=1, log_every=10_000))


# ----------------------------------------------------------------------------
# the projected attacker must keep the fabricated attacker's training selection
# ----------------------------------------------------------------------------
def test_projected_variant_keeps_oversampling():
    import numpy as np
    from pafl.fl.variants import build_variant
    kw = dict(n_clients=4, window=10, seed=0, steps_per_client=1200)
    sc_f, inv, cols = build_variant("synthetic", "fabricated", 0.5, kw["n_clients"],
                                    kw["window"], kw["seed"], steps_per_client=kw["steps_per_client"])
    sc_p, _, _ = build_variant("synthetic", "projected", 0.5, kw["n_clients"],
                               kw["window"], kw["seed"], steps_per_client=kw["steps_per_client"])
    mal_f = [c for c in sc_f["clients"] if c.is_malicious]
    mal_p = [c for c in sc_p["clients"] if c.is_malicious]
    assert mal_f and len(mal_f) == len(mal_p)
    for a, b in zip(mal_f, mal_p):
        assert a.train_index is not None and np.array_equal(a.train_index, b.train_index)
        assert a.train.shape == b.train.shape           # same size, same oversampling
        assert not np.allclose(a.train, b.train)         # but the data moved
        assert inv.batch_verdict(b.raw)["admitted"]      # and it now passes the check


def test_real_scenario_splices_attacks_into_the_checked_batch():
    import numpy as np
    import pandas as pd
    from pafl.data.synthetic import simulate, default_attacks
    from pafl.fl.scenario_real import RealScenarioConfig, build_real_scenario, splice_attacks
    from pafl.data.loaders import feature_columns
    # two simulator runs stand in for a real normal and attack record
    normal = simulate(6000, seed=1); normal["ATT_FLAG"] = 0
    attack = simulate(3000, seed=2, attacks=default_attacks(3000, seed=2, n=6))
    cols = feature_columns(normal)
    rs = np.random.default_rng(0)
    spliced = splice_attacks(normal.iloc[:1000], attack, cols, 0.25, rs)
    assert len(spliced) == 1000
    # about a quarter, whole segments; below 0.25 when placed segments overlap
    assert 0.15 <= spliced["ATT_FLAG"].mean() <= 0.30
    sc = build_real_scenario(normal, attack, RealScenarioConfig(n_clients=4, malicious_fraction=0.5,
                                                                seed=0))
    mal = [c for c in sc["clients"] if c.is_malicious]
    hon = [c for c in sc["clients"] if not c.is_malicious]
    assert len(mal) == 2 and len(hon) == 2
    for c in mal:
        assert c.train_index is not None and len(c.train_index) == len(c.train)
        assert int(c.raw["ATT_FLAG"].sum()) == 0             # labels hidden from the trainer
        assert len(c.raw) == len(hon[0].raw)                 # shards keep their size


def test_scaler_gives_constant_channels_unit_scale():
    import numpy as np
    from pafl.data.loaders import Scaler
    X = np.column_stack([np.ones(100), np.random.default_rng(0).normal(size=100)]).astype(np.float32)
    sc = Scaler.fit(X)
    assert sc.std[0] == 1.0 and abs(sc.std[1] - X[:, 1].std()) < 1e-6
    z = sc(np.array([[2.0, 0.0]], np.float32))
    assert abs(z[0, 0] - 1.0) < 1e-6           # a state change is one sigma, not 1e8


def test_gated_variant_excludes_rejected_clients():
    # identical settings, so the gated federation is the projected one minus
    # exactly the clients whose batch the check rejects
    from pafl.fl.variants import build_variant
    sc_p, inv, _ = build_variant("synthetic", "projected", 0.5, 4, 10, 0, steps_per_client=1200,
                                 target_violating=0.0)
    sc_g, _, _ = build_variant("synthetic", "gated", 0.5, 4, 10, 0, steps_per_client=1200,
                               target_violating=0.0)
    n_rej = sum(not v["admitted"] for v in sc_p["physics_verdicts"])
    assert sc_g["n_excluded_by_gate"] == n_rej
    assert len(sc_g["clients"]) == len(sc_p["clients"]) - n_rej
    assert all(inv.batch_verdict(c.raw)["admitted"] for c in sc_g["clients"] if c.is_malicious)


def test_verdicts_cover_honest_clients_and_gate_counts_add_up():
    """Every client gets a verdict; the malicious-only rate keeps its meaning; the
    gate's exclusion count is the sum of its malicious and honest exclusions."""
    from pafl.fl.variants import build_variant
    sc, inv, _ = build_variant("synthetic", "fabricated", 0.5, 4, 10, 0, steps_per_client=1200)
    v = sc["physics_verdicts"]
    assert len(v) == len(sc["clients"])
    assert {x["is_malicious"] for x in v} == {True, False}
    mal = [x for x in v if x["is_malicious"]]
    hon = [x for x in v if not x["is_malicious"]]
    assert abs(sc["physics_admitted_rate"] - sum(x["admitted"] for x in mal) / len(mal)) < 1e-12
    assert abs(sc["honest_physics_admitted_rate"] - sum(x["admitted"] for x in hon) / len(hon)) < 1e-12
    assert sc["n_honest_rejected"] == sum(not x["admitted"] for x in hon)
    sc_g, _, _ = build_variant("synthetic", "gated", 0.5, 4, 10, 0, steps_per_client=1200,
                               target_violating=0.0)
    assert sc_g["n_excluded_by_gate"] == sc_g["n_malicious_excluded_by_gate"] + sc_g["n_honest_excluded_by_gate"]
    assert sc_g["n_honest_excluded_by_gate"] == sum(not x["admitted"] for x in sc_g["physics_verdicts"]
                                                    if not x["is_malicious"])
    sc_h, _, _ = build_variant("synthetic", "honest_only", 0.5, 4, 10, 0, steps_per_client=1200)
    assert sc_h["physics_admitted_rate"] is None
    assert all(not x["is_malicious"] for x in sc_h["physics_verdicts"])
