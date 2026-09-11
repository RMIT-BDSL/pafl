"""Assemble a federation: sites, malicious clients, fabrications, eval sets."""
from __future__ import annotations
from dataclasses import dataclass
import numpy as np
import pandas as pd

from ..data.loaders import ClientData, Scaler, feature_columns, make_windows
from ..data.synthetic import simulate, default_attacks, PlantParams, misspecified
from ..attacks.recipe_a import fabricate
from ..utils.logging import get_logger

log = get_logger("pafl.scenario")


@dataclass
class ScenarioConfig:
    n_clients: int = 10
    malicious_fraction: float = 0.2
    fabrication: str = "channel_roll"
    steps_per_client: int = 6000
    window: int = 10
    seed: int = 0
    test_steps: int = 8000
    val_steps: int = 3000
    root_steps: int = 800            # the small clean set FLTrust needs
    attacks_in_test: int = 8
    poison_strength: float = 0.5     # share of a malicious client's windows drawn from attacks
    attacks_in_malicious_batch: int = 10
    update_attack: str | None = None     # if set, malicious clients keep honest data, attack the update
    update_attack_kw: dict | None = None


def build_synthetic_scenario(cfg: ScenarioConfig) -> dict:
    """A federation of simulated plants that differ from one another.

    Site heterogeneity is deliberate. Each client gets its own setpoints, pump
    ratings and tank areas, so the honest updates do not cluster tightly. That
    is the condition under which robust aggregation is known to weaken, and
    pretending otherwise would flatter the baselines.
    """
    rs = np.random.default_rng(cfg.seed)
    n_mal = int(round(cfg.n_clients * cfg.malicious_fraction))
    mal_ids = set(rs.choice(cfg.n_clients, size=n_mal, replace=False).tolist()) if n_mal else set()

    site_frames: list[pd.DataFrame] = []
    for i in range(cfg.n_clients):
        shift = float(rs.uniform(-1.0, 1.0))
        site_frames.append(simulate(cfg.steps_per_client, seed=cfg.seed * 1000 + i,
                                    site_shift=shift))

    cols = feature_columns(site_frames[0])
    pooled = np.concatenate([f[cols].to_numpy(np.float32) for f in site_frames])
    scaler = Scaler.fit(pooled)

    clients: list[ClientData] = []
    for i, df in enumerate(site_frames):
        malicious = i in mal_ids
        if malicious and cfg.update_attack:
            # update-space attacker: honest data, crafted update
            batch = df
            W, y = make_windows(batch, cfg.window, cols)
            clients.append(ClientData(i, scaler(W).astype(np.float32), y, batch,
                                      is_malicious=True,
                                      update_attack=cfg.update_attack,
                                      update_attack_kw=cfg.update_attack_kw))
            continue
        if malicious:
            # Attacked telemetry from this client's own plant, fabricated so the
            # physics no longer holds, then presented to the local trainer as if
            # it were normal.
            atk = simulate(cfg.steps_per_client, seed=cfg.seed * 1000 + i, site_shift=shift,
                           attacks=default_attacks(cfg.steps_per_client, seed=i,
                                                   n=cfg.attacks_in_malicious_batch))
            if cfg.fabrication == "recipe_b":
                from ..attacks.recipe_b import fabricate_recipe_b
                batch = fabricate_recipe_b(atk, None, cols, window=cfg.window,
                                           seed=cfg.seed + i)
            else:
                batch = fabricate(atk, cfg.fabrication, seed=cfg.seed + i)
            batch["ATT_FLAG"] = 0
            W, y_true = make_windows(atk, cfg.window, cols)     # labels of the underlying attack
            W_fab, _ = make_windows(batch, cfg.window, cols)
            # The poisoning objective for a reconstruction detector is not a label
            # flip -- an autoencoder never reads the label. It is exposure: the
            # attacker oversamples windows that contain the attack so the shared
            # model learns to reconstruct that signature well, and it stops
            # looking anomalous to everyone else in the federation.
            atk_idx = np.where(y_true == 1)[0]
            ok_idx = np.where(y_true == 0)[0]
            sel = None
            if atk_idx.size and cfg.poison_strength > 0:
                n_take = int(len(W_fab) * cfg.poison_strength)
                draw_a = rs.choice(atk_idx, size=n_take, replace=True)
                draw_n = rs.choice(ok_idx, size=len(W_fab) - n_take, replace=True) \
                    if ok_idx.size else draw_a
                sel = np.concatenate([draw_a, draw_n])
                rs.shuffle(sel)
                W, y = W_fab[sel], np.zeros(len(sel), np.int64)
            else:
                W, y = W_fab, np.zeros(len(W_fab), np.int64)
        else:
            batch = df
            sel = None
            W, y = make_windows(batch, cfg.window, cols)
        clients.append(ClientData(i, scaler(W).astype(np.float32), y, batch,
                                  is_malicious=malicious,
                                  fabrication=cfg.fabrication if malicious else None,
                                  train_index=sel))

    val_df = simulate(cfg.val_steps, seed=cfg.seed + 90_001)
    test_df = simulate(cfg.test_steps, seed=cfg.seed + 90_002,
                       attacks=default_attacks(cfg.test_steps, seed=cfg.seed + 7,
                                               n=cfg.attacks_in_test))
    root_df = simulate(cfg.root_steps, seed=cfg.seed + 90_003)

    Xv, _ = make_windows(val_df, cfg.window, cols)
    Xt, yt = make_windows(test_df, cfg.window, cols)
    Xr, _ = make_windows(root_df, cfg.window, cols)

    log.info("federation: %d clients, %d malicious (%s), %d features, %d train windows each",
             cfg.n_clients, n_mal, cfg.fabrication if n_mal else "none",
             len(cols), len(clients[0].train))

    return {
        "clients": clients,
        "columns": cols,
        "scaler": scaler,
        "eval_sets": {
            "clean_val": (scaler(Xv).astype(np.float32), np.zeros(len(Xv), np.int64)),
            "test": (scaler(Xt).astype(np.float32), yt),
        },
        "root_data": scaler(Xr).astype(np.float32),
        "n_malicious": n_mal,
        "test_attack_rate": float(yt.mean()),
    }
