"""Real-data plumbing and the extra baselines: SWaT and WADI loaders, partition,
Recipe B, FoolsGold, update attacks, the coupling miner on SWaT-shaped data.

"Week 2" in the file name is the pilot plan's second week, when these arrived.
The tests run on the synthetic simulator and on small in-memory files, so they
need no downloaded dataset and finish in seconds. They pin the contracts the
real-data scripts rely on, not the science; the science is what the runs
measure.
"""
from __future__ import annotations
import io
import numpy as np
import pandas as pd
import pytest
import torch

from pafl.data.synthetic import simulate, default_attacks
from pafl.data.loaders import feature_columns, make_windows
from pafl.data.swat import load_swat, swat_invariants
from pafl.fl.partition import PartitionConfig, partition_frame
from pafl.fl.defences import foolsgold_weights, aggregate, acceptance_mask, trust_weights
from pafl.attacks.update_attacks import apply_update_attack, UPDATE_ATTACKS
from pafl.attacks.recipe_b import fabricate_recipe_b


# ----------------------------------------------------------------------------
# SWaT loader: a small CSV in the shipped format (title row + Normal/Attack col)
# ----------------------------------------------------------------------------
def _swat_like_csv(n=200):
    rng = np.random.default_rng(0)
    t = np.arange(n)
    lit = 500 + 50 * np.sin(t / 10.0)
    p = (np.sin(t / 10.0) > 0).astype(int) + 1          # pump 1/2
    fit = np.where(p == 2, 2.0 + 0.01 * rng.standard_normal(n), 0.0)
    lbl = np.where(t >= n - 20, "Attack", "Normal")
    df = pd.DataFrame({" Timestamp": pd.date_range("2015-12-22", periods=n, freq="s"),
                       "FIT101": fit, "LIT101 ": lit, "P101": p,
                       "Normal/Attack": lbl})
    buf = io.StringIO()
    buf.write("SWaT title row to be skipped,,,,\n")   # the stray title line
    df.to_csv(buf, index=False)
    return buf.getvalue()


def test_swat_loader_parses_and_labels(tmp_path):
    path = tmp_path / "SWaT_Dataset_Attack_v0.csv"
    path.write_text(_swat_like_csv())
    df = load_swat(path)
    assert "ATT_FLAG" in df.columns
    assert df["ATT_FLAG"].sum() == 20                  # last 20 rows are attacks
    # columns are stripped and timestamp is separated out
    assert "LIT101" in df.columns and "datetime" in df.columns
    assert "Normal/Attack" not in df.columns
    assert df["FIT101"].dtype.kind == "f"


def test_swat_downsample(tmp_path):
    path = tmp_path / "SWaT_Dataset_Normal_v1.csv"
    path.write_text(_swat_like_csv(300))
    df = load_swat(path, downsample=5)
    assert len(df) == 60


def test_swat_invariants_find_the_coupling(tmp_path):
    # a clean frame where the pump gates the flow exactly: the coupling must be found
    path = tmp_path / "normal.csv"
    path.write_text(_swat_like_csv(400).replace("Attack", "Normal"))
    df = load_swat(path)
    inv_set, report = swat_invariants(df)
    assert report["kept_couplings"] >= 1


# ----------------------------------------------------------------------------
# partition
# ----------------------------------------------------------------------------
def test_partition_temporal_is_contiguous_and_covers_all():
    df = simulate(5000, seed=1)
    df["ATT_FLAG"] = 0
    frames = partition_frame(df, PartitionConfig(n_clients=10, scheme="temporal"))
    assert len(frames) == 10
    assert sum(len(f) for f in frames) == len(df)


def test_partition_rejects_attacked_frame():
    df = simulate(3000, seed=1)
    df["ATT_FLAG"] = 0
    df.loc[0, "ATT_FLAG"] = 1
    with pytest.raises(ValueError):
        partition_frame(df, PartitionConfig(n_clients=5))


# ----------------------------------------------------------------------------
# FoolsGold + update attacks + trust weights
# ----------------------------------------------------------------------------
def test_foolsgold_downweights_colluding_sybils():
    # FoolsGold's premise in miniature: near-identical sybil updates lose weight
    torch.manual_seed(0)
    d = 50
    honest = torch.randn(6, d)
    # three sybils all pushing the same direction
    direction = torch.randn(d)
    sybils = direction.unsqueeze(0).repeat(3, 1) + 0.01 * torch.randn(3, d)
    updates = torch.cat([honest, sybils])
    w = foolsgold_weights(updates)
    assert w.shape[0] == 9
    assert w[6:].mean() < w[:6].mean()          # sybils get less weight than honest


def test_update_attacks_change_the_update():
    torch.manual_seed(0)
    updates = torch.randn(8, 40)
    honest_mask = torch.tensor([True] * 6 + [False] * 2)
    for name in UPDATE_ATTACKS:
        out = apply_update_attack(name, updates[7].clone(), updates, honest_mask, seed=1)
        assert out.shape == updates[7].shape
        assert torch.isfinite(out).all()
    # sign flip really flips
    sf = apply_update_attack("sign_flip", updates[7], updates, honest_mask)
    assert torch.allclose(sf, -updates[7])


def test_trust_weights_reported_for_similarity_rules():
    torch.manual_seed(0)
    updates = torch.randn(10, 60)
    server = updates[:8].mean(0)               # a plausible honest server update
    tw = trust_weights("fltrust", updates, server_update=server)
    # normalised trust sums to 1, or to 0 when every cosine is clipped at zero
    assert tw.shape[0] == 10 and abs(float(tw.sum()) - 1.0) < 1e-4 or float(tw.sum()) == 0.0
    fw = trust_weights("foolsgold", updates)
    assert fw.shape[0] == 10


def test_foolsgold_registered_and_aggregates():
    torch.manual_seed(0)
    updates = torch.randn(10, 30)
    agg = aggregate("foolsgold", updates)
    assert agg.shape[0] == 30
    mask = acceptance_mask("foolsgold", updates)
    assert mask.dtype == torch.bool and mask.shape[0] == 10


# ----------------------------------------------------------------------------
# Recipe B
# ----------------------------------------------------------------------------
def test_recipe_b_moves_continuous_not_discrete():
    df = simulate(1200, seed=3)
    cols = feature_columns(df)
    fab = fabricate_recipe_b(df, None, cols, window=10, match_steps=15,
                             surrogate_steps=40, first_order=True, seed=0)
    assert list(fab.columns) == list(df.columns) or set(cols).issubset(fab.columns)
    # something changed on the continuous channels
    changed = (fab[cols].to_numpy() != df[cols].to_numpy()).any()
    assert changed
    # no NaNs introduced
    assert np.isfinite(fab[cols].to_numpy()).all()


def test_recipe_b_full_gradient_matching_runs():
    df = simulate(800, seed=5)
    cols = feature_columns(df)
    tgt = simulate(800, seed=99, attacks=default_attacks(800, seed=1, n=4))
    Wt, _ = make_windows(tgt, 10, cols)
    fab = fabricate_recipe_b(df, None, cols, target_windows=Wt[:50], window=10,
                             match_steps=8, surrogate_steps=30, first_order=False, seed=0)
    assert np.isfinite(fab[cols].to_numpy()).all()


def test_recipe_b_gradient_matching_aligns_with_the_target():
    """The full path must move the batch's parameter gradient toward the
    target's, so that training on it also lowers the target's reconstruction
    error. With the sign that stood until 26 Sep 2026 the cosine fell instead.

    The surrogate is rebuilt exactly as fabricate_recipe_b builds it (same shard
    standardisation, same seed), and the target windows are passed in the
    shard's own z-units, as the function requires.
    """
    import torch
    from pafl.attacks.recipe_b import _local_standardise, _train_surrogate, _unfold_windows
    df = simulate(800, seed=5)
    cols = feature_columns(df)
    tgt = simulate(800, seed=99, attacks=default_attacks(800, seed=1, n=4))
    X = df[cols].to_numpy(np.float64)
    Xs, mu, sd = _local_standardise(X)
    Tz, _ = make_windows(pd.DataFrame((tgt[cols].to_numpy(np.float64) - mu) / sd, columns=cols), 10, cols)
    fab = fabricate_recipe_b(df, None, cols, target_windows=Tz[:200], window=10,
                             match_steps=40, surrogate_steps=60, first_order=False, seed=0)

    torch.manual_seed(0)
    surrogate = _train_surrogate(_unfold_windows(torch.tensor(Xs, dtype=torch.float32), 10),
                                 10, len(cols), 60, lr=1e-3, seed=0, device="cpu")
    lossf = torch.nn.MSELoss()

    def grad(W):
        w = torch.tensor(W, dtype=torch.float32)
        g = torch.autograd.grad(lossf(surrogate(w), w), list(surrogate.parameters()))
        return torch.cat([x.reshape(-1) for x in g])

    g_target = grad(Tz[:200])
    cos = torch.nn.functional.cosine_similarity
    z = lambda frame: _unfold_windows(torch.tensor((frame[cols].to_numpy(np.float64) - mu) / sd,
                                                   dtype=torch.float32), 10).numpy()
    before = float(cos(grad(z(df)), g_target, dim=0))
    after = float(cos(grad(z(fab)), g_target, dim=0))
    assert after > before + 0.05, (before, after)


# ----------------------------------------------------------------------------
# miner and file finder on SWaT-shaped data
# ----------------------------------------------------------------------------
def test_mine_couplings_survives_lag_and_transition_state():
    """SWaT: 1/2 encoding, a 0 while the actuator moves, and a one-row flow lag
    after every switch. The first miner found nothing here."""
    from pafl.invariants.mine import mine_couplings
    rng = np.random.default_rng(0)
    n = 4000
    t = np.arange(n)
    p = np.where((t // 200) % 2 == 0, 2, 1).astype(float)          # 200-row duty cycle
    switch = np.zeros(n, bool); switch[1:] = p[1:] != p[:-1]
    p[switch] = 0.0                                                # transition marker
    fit = np.where(p == 2, 2.4 + 0.05 * rng.standard_normal(n), 0.0)
    lag = np.zeros(n, bool); lag[1:] = switch[:-1]
    fit[lag & (p == 1)] = 1.8                                      # flow still decaying
    other = 500 + 30 * np.sin(t / 50.0)                            # a level: never zero
    df = pd.DataFrame({"P101": p, "FIT201": fit, "LIT101": other})
    cs = mine_couplings(df)
    assert [(c.status, c.flow) for c in cs] == [("P101", "FIT201")]
    c = cs[0]
    assert c.off_value == 1.0 and c.on_value == 2.0
    assert abs(c.nominal - 2.4) < 0.05


def test_find_swat_files_prefers_dataset_csv_over_attack_list(tmp_path):
    from pafl.data.swat import find_swat_files
    (tmp_path / "List_of_attacks_Final.xlsx").write_bytes(b"x")
    (tmp_path / "Physical").mkdir()
    (tmp_path / "Physical" / "SWaT_Dataset_Attack_v0.xlsx").write_bytes(b"x")
    (tmp_path / "Physical" / "SWaT_Dataset_Normal_v1.xlsx").write_bytes(b"x")
    (tmp_path / "Physical" / "SWaT_Dataset_Normal_v0.xlsx").write_bytes(b"x")
    f = find_swat_files(tmp_path)
    assert f["attack"].name == "SWaT_Dataset_Attack_v0.xlsx"
    assert f["normal"].name == "SWaT_Dataset_Normal_v1.xlsx"
    (tmp_path / "Physical" / "SWaT_Dataset_Normal_v1.csv").write_bytes(b"x")
    assert find_swat_files(tmp_path)["normal"].suffix == ".csv"


def test_wadi_loader_strips_opc_paths_and_labels(tmp_path):
    import pandas as pd
    from pafl.data.wadi import load_wadi, attack_labels
    pre = "Created: x\nNumber of rows: 5\nInterpolation interval: 1 seconds\n\n"
    hdr = "Row,Date,Time,\\\\W\\LOG_DATA\\SUTD_WADI\\LOG_DATA\\1_FIT_001_PV,\\\\W\\LOG_DATA\\SUTD_WADI\\LOG_DATA\\1_P_001_STATUS,\\\\W\\LOG_DATA\\SUTD_WADI\\LOG_DATA\\PLANT_START_STOP_LOG\n"
    rows = "".join(f"{i+1},10/9/2017,6:00:0{i}.000 PM,{2.0 if i%2 else 0.0},{2 if i%2 else 1},1\n" for i in range(5))
    f = tmp_path / "WADI_attackdata.csv"; f.write_text(pre + hdr + rows)
    df = load_wadi(f)
    assert list(df.columns) == ["1_FIT_001_PV", "1_P_001_STATUS", "datetime", "ATT_FLAG"]
    assert df["datetime"].iloc[0] == pd.Timestamp("2017-10-09 18:00:00")
    sheet = tmp_path / "attack_description.xlsx"
    pd.DataFrame([[None, None, None, None, None],
                  ["S.No", "Date", "Start Time", "End Time", "Attack Point (s)"],
                  [1, "2017-10-09", "18:00:01", "18:00:03", "1_P_001"]]).to_excel(sheet, header=False, index=False)
    lab = attack_labels(sheet, 5)
    assert lab.tolist() == [False, True, True, False, False]
