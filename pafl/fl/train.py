"""The federated loop, with checkpointing and per-round bookkeeping.

Threat model in code. Honest clients train only on their own clean windows.
A malicious client trains on a fabricated batch that includes attack windows
presented as normal, which for a reconstruction detector is the natural targeted
objective: teach the shared model to reconstruct attacks well, so they stop
looking anomalous to everyone.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
import time
import numpy as np
import torch
import torch.nn as nn

from .models import build_model, get_flat_params, set_flat_params, n_params
from .defences import aggregate, acceptance_mask, trust_weights
from ..attacks.update_attacks import apply_update_attack
from ..data.loaders import ClientData
from ..eval.metrics import threshold_from_clean, detection_report, detection_delay
from ..utils.ckpt import save_state, load_state, interrupted
from ..utils.logging import get_logger

log = get_logger("pafl.fl")


@dataclass
class FLConfig:
    rounds: int = 30
    local_epochs: int = 1
    batch_size: int = 128
    lr: float = 1e-3
    model: str = "window_ae"
    window: int = 10
    defence: str = "fedavg"
    trim_frac: float = 0.2
    clip: float | None = None
    krum_multi: int = 1
    seed: int = 0
    device: str = "cpu"
    log_every: int = 5
    threshold_quantile: float = 0.995
    foolsgold_kappa: float = 1.0
    record_trust: bool = False        # keep the per-round, per-client trust vector


def _local_train(model: nn.Module, X: np.ndarray, cfg: FLConfig, gen: torch.Generator) -> torch.Tensor:
    """One client's local step. Returns the delta from the incoming global model."""
    dev = torch.device(cfg.device)
    model = model.to(dev)
    before = get_flat_params(model).clone()
    opt = torch.optim.Adam(model.parameters(), lr=cfg.lr)
    lossf = nn.MSELoss()
    xt = torch.from_numpy(X).to(dev)
    n = xt.shape[0]
    model.train()
    for _ in range(cfg.local_epochs):
        perm = torch.randperm(n, generator=gen)
        for i in range(0, n, cfg.batch_size):
            xb = xt[perm[i:i + cfg.batch_size]]
            opt.zero_grad()
            loss = lossf(model(xb), xb)
            loss.backward()
            opt.step()
    return get_flat_params(model) - before


@torch.no_grad()
def _scores(model: nn.Module, X: np.ndarray, device: str, chunk: int = 4096) -> np.ndarray:
    dev = torch.device(device)
    model = model.to(dev).eval()
    out = []
    for i in range(0, len(X), chunk):
        xb = torch.from_numpy(X[i:i + chunk]).to(dev)
        out.append(model.score(xb).cpu().numpy())
    return np.concatenate(out) if out else np.zeros(0)


def run_federation(clients: list[ClientData], eval_sets: dict[str, tuple[np.ndarray, np.ndarray]],
                   cfg: FLConfig, root_data: np.ndarray | None = None,
                   ckpt_path: str | Path | None = None) -> dict:
    """Train the federation and report detection on the held-out sets.

    eval_sets maps a name to (windows, labels). 'clean_val' is required, because
    the alarm threshold is calibrated on it and never on the test set.
    """
    if "clean_val" not in eval_sets:
        raise ValueError("eval_sets must contain 'clean_val' for threshold calibration")
    torch.manual_seed(cfg.seed)
    gen = torch.Generator().manual_seed(cfg.seed)
    dev = torch.device(cfg.device)

    n_ch = len(clients[0].train[0]) // cfg.window
    global_model = build_model(cfg.model, n_channels=n_ch, window=cfg.window).to(dev)

    state = load_state(ckpt_path) if ckpt_path else None
    start_round = 0
    history: list[dict] = []
    if state:
        set_flat_params(global_model, state["params"])
        start_round = state["round"] + 1
        history = state["history"]
        log.info("resumed from round %d", start_round)

    n_mal = sum(c.is_malicious for c in clients)
    honest_mask = torch.tensor([not c.is_malicious for c in clients], device=dev)
    n_clients = len(clients)
    fg_history = None
    trust_log: list[dict] = []
    if state:
        fg_history = state.get("fg_history")
        trust_log = state.get("trust_log", [])
    t0 = time.time()

    for rnd in range(start_round, cfg.rounds):
        gp = get_flat_params(global_model).clone()
        updates, sizes = [], []
        for c in clients:
            local = build_model(cfg.model, n_channels=n_ch, window=cfg.window).to(dev)
            set_flat_params(local, gp)
            updates.append(_local_train(local, c.train, cfg, gen))
            sizes.append(len(c.train))
        U = torch.stack(updates)

        # update-space attacks replace a malicious client's honest update with a
        # crafted vector. Data fabrications (Recipe A/B) already live in the
        # client's training data and need no hook here.
        if fg_history is None:
            fg_history = torch.zeros_like(U)
        for i, c in enumerate(clients):
            atk = getattr(c, "update_attack", None)
            if atk:
                U[i] = apply_update_attack(atk, U[i], U, honest_mask,
                                           **getattr(c, "update_attack_kw", {}) or {})

        server_update = None
        if cfg.defence == "fltrust":
            if root_data is None:
                raise ValueError("fltrust needs root_data: a small clean set held by the server")
            srv = build_model(cfg.model, n_channels=n_ch, window=cfg.window).to(dev)
            set_flat_params(srv, gp)
            server_update = _local_train(srv, root_data, cfg, gen)

        kw = dict(n_malicious=max(n_mal, 1), multi=cfg.krum_multi,
                  trim_frac=cfg.trim_frac, clip=cfg.clip, server_update=server_update,
                  history=fg_history + U, kappa=cfg.foolsgold_kappa,
                  weights=torch.tensor(sizes, dtype=torch.float32, device=dev))
        agg = aggregate(cfg.defence, U, **kw)
        mask = acceptance_mask(cfg.defence, U, **kw)
        set_flat_params(global_model, gp + agg)

        # trust instrumentation: the per-client weight a similarity rule assigned,
        # plus the geometry that explains it. This is the raw material for the
        # 4b question -- does projecting a batch onto the physics manifold raise
        # its trust while it still carries poison.
        if cfg.record_trust or cfg.defence in ("fltrust", "foolsgold"):
            tw = trust_weights(cfg.defence, U, **kw).detach().cpu().numpy()
            honest_mean = U[honest_mask].mean(0) if honest_mask.any() else U.mean(0)
            hm = honest_mean / (honest_mean.norm() + 1e-12)
            cos_honest = ((U / (U.norm(dim=1, keepdim=True) + 1e-12)) @ hm
                          ).detach().cpu().numpy()
            trust_log.append({
                "round": rnd,
                "trust": tw.tolist(),
                "cos_to_honest_mean": cos_honest.tolist(),
                "is_malicious": [bool(c.is_malicious) for c in clients],
            })

        fg_history = fg_history + U

        mal_idx = [i for i, c in enumerate(clients) if c.is_malicious]
        rec = {
            "round": rnd,
            "malicious_accepted": float(mask[mal_idx].float().mean()) if mal_idx else 0.0,
            "honest_accepted": float(mask[[i for i, c in enumerate(clients)
                                           if not c.is_malicious]].float().mean()),
            "update_norm_mean": float(U.norm(dim=1).mean()),
            "update_norm_malicious": float(U[mal_idx].norm(dim=1).mean()) if mal_idx else 0.0,
        }
        history.append(rec)
        if rnd % cfg.log_every == 0 or rnd == cfg.rounds - 1:
            log.info("round %3d/%d  mal_accept %.2f  |u| %.4f",
                     rnd, cfg.rounds, rec["malicious_accepted"], rec["update_norm_mean"])
        if ckpt_path:
            save_state(ckpt_path, {"round": rnd, "params": get_flat_params(global_model),
                                   "history": history, "fg_history": fg_history,
                                   "trust_log": trust_log})
        if interrupted():
            log.warning("stopping early at round %d; checkpoint written", rnd)
            break

    clean_val = eval_sets["clean_val"][0]
    thr = threshold_from_clean(_scores(global_model, clean_val, cfg.device),
                               quantile=cfg.threshold_quantile)
    results, raw_scores = {}, {}
    for name, (X, y) in eval_sets.items():
        if name == "clean_val":
            continue
        sc = _scores(global_model, X, cfg.device)
        rep = detection_report(sc, y, thr)
        rep.update(detection_delay(sc, y, thr))
        results[name] = rep
        raw_scores[name] = sc

    return {
        "config": asdict(cfg),
        "n_clients": len(clients),
        "n_malicious": n_mal,
        "n_params": n_params(global_model),
        "threshold": thr,
        "history": history,
        "trust_log": trust_log,
        "results": results,
        "scores": raw_scores,
        "wall_seconds": round(time.time() - t0, 2),
        "malicious_acceptance_rate": float(np.mean([h["malicious_accepted"] for h in history]))
            if history and n_mal else 0.0,
    }
