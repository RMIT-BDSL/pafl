"""The federated loop, with checkpointing and per-round bookkeeping.

Threat model in code. Honest clients train only on their own clean windows.
A malicious client trains on a batch that carries attack windows presented as
normal, which for a reconstruction detector is the natural targeted
objective: teach the shared model to reconstruct attacks well, so they stop
looking anomalous to everyone. The scenario builders (fl.scenario,
fl.scenario_real, fl.variants) decide what that batch is: attack rows replayed
as they are (`splice_only`, the paper's "replay"), fabricated on top (the
`fabricated` federation, the paper's "naive attack"), or also projected onto the
invariants (`projected`, the "physics-aware attack"). This loop never sees the
physics check; in the `gated` federation the rejected clients are simply absent
from `clients`. The only attacker this module handles itself is an update-space
one, which replaces its update after local training.

One round. Every client starts from the global model and trains for
`local_epochs` passes over its windows: MSE reconstruction loss, Adam at `lr`
with a fresh optimiser state each round, mini-batches of `batch_size` windows.
It returns the change in its parameters; the aggregation rule (fl.defences)
combines the changes and the server adds the result to the global model.

After the last round the detector is scored once. The alarm threshold is the
`threshold_quantile` (0.995) quantile of the final model's scores on the clean
validation slice, and a window alarms when its score is strictly above it. Every
other eval set is scored at that single threshold. On the real records 'test'
is every window of the attack record; 'test_targeted' and 'test_untargeted'
hold only attack windows, so recall is their one meaningful field.
Targeted-attack recall, the paper's main measure, is
results["test_targeted"]["recall"]: the fraction of the attack windows the
malicious clients try to hide (those touching a target segment) that the final
model flags.

Paper settings: 25 rounds and 2 local epochs, which the scripts pass for every
paper run (see scripts/reproduce.sh). The FLConfig defaults for those two
fields are 30 and 1, so FLConfig() alone does not reproduce a paper run; the
other defaults are what the paper's runs use.

Determinism. torch.manual_seed(seed) fixes the initial global model, which is
therefore the same for every federation and every rule of a seed. One
torch.Generator drives every mini-batch shuffle, drawn in client order and then
by the FLTrust server, so the order a given client sees depends on how many
clients come before it: the honest-only run differs from the attacked one in
mini-batch order as well as in composition. A checkpoint does not store the
generator's state, so a resumed run is not bit-identical to one that ran
straight through; the scripts do not checkpoint inside a run.
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
    """Settings for one federated run. See the module docstring for which
    defaults match the paper (all but `rounds` and `local_epochs`)."""
    rounds: int = 30                  # paper: 25, set by the scripts
    local_epochs: int = 1             # paper: 2, set by the scripts
    batch_size: int = 128             # windows per Adam step (a mini-batch)
    lr: float = 1e-3                  # Adam learning rate, clients and FLTrust server alike
    model: str = "window_ae"
    window: int = 10                  # rows per window; must match the scenario's window
    defence: str = "fedavg"           # a key of fl.defences.DEFENCES
    trim_frac: float = 0.2            # trimmed_mean: share trimmed from each end
    clip: float | None = None         # norm_clip bound; None = the round's median update norm
    krum_multi: int = 1               # Krum: updates averaged (1 = classic Krum)
    seed: int = 0
    device: str = "cpu"
    log_every: int = 5
    threshold_quantile: float = 0.995   # alarm threshold: this quantile of clean-val scores
    foolsgold_kappa: float = 1.0      # FoolsGold's logit confidence
    record_trust: bool = False        # keep the per-round, per-client trust vector


def _local_train(model: nn.Module, X: np.ndarray, cfg: FLConfig, gen: torch.Generator) -> torch.Tensor:
    """One client's local step. Returns the delta from the incoming global model.

    A new Adam optimiser per call, so moment estimates do not carry over between
    rounds. The last mini-batch of each pass may be short. The FLTrust server
    uses this same function on the root set.
    """
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
    """Anomaly score of every window of X, in chunks to bound memory."""
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
    root_data is FLTrust's clean server-side set, required for that rule only.
    The returned dict carries a detection report per eval set under "results",
    the per-round history, the trust log and `malicious_acceptance_rate`, the
    mean over rounds of the share of malicious updates the rule accepted.
    """
    if "clean_val" not in eval_sets:
        raise ValueError("eval_sets must contain 'clean_val' for threshold calibration")
    torch.manual_seed(cfg.seed)                    # the initial global model
    gen = torch.Generator().manual_seed(cfg.seed)  # every mini-batch shuffle
    dev = torch.device(cfg.device)

    # The channel count is read off the flattened window width, so a cfg.window
    # that differs from the scenario's window silently builds the wrong model.
    n_ch = len(clients[0].train[0]) // cfg.window
    global_model = build_model(cfg.model, n_channels=n_ch, window=cfg.window).to(dev)

    state = load_state(ckpt_path) if ckpt_path else None
    start_round = 0
    history: list[dict] = []
    if state:
        # restores the model and bookkeeping, not `gen`: see the module docstring
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
        # client's training data and need no hook here. The attacker is
        # omniscient: it sees every update and the honest mask. Clients are
        # replaced in order, so a later attacker sees earlier crafted vectors.
        # fg_history is FoolsGold's per-client running sum; it is kept for
        # every rule and read only by foolsgold.
        if fg_history is None:
            fg_history = torch.zeros_like(U)
        for i, c in enumerate(clients):
            atk = getattr(c, "update_attack", None)
            if atk:
                U[i] = apply_update_attack(atk, U[i], U, honest_mask,
                                           **getattr(c, "update_attack_kw", {}) or {})

        server_update = None
        if cfg.defence == "fltrust":
            # the server's own update from the same global model; it draws from
            # `gen` too, so FLTrust runs see different shuffles after round 0
            if root_data is None:
                raise ValueError("fltrust needs root_data: a small clean set held by the server")
            srv = build_model(cfg.model, n_channels=n_ch, window=cfg.window).to(dev)
            set_flat_params(srv, gp)
            server_update = _local_train(srv, root_data, cfg, gen)

        # One keyword set for every rule. n_malicious is Krum's f, set from the
        # true number of malicious clients present; weights are FedAvg's.
        kw = dict(n_malicious=max(n_mal, 1), multi=cfg.krum_multi,
                  trim_frac=cfg.trim_frac, clip=cfg.clip, server_update=server_update,
                  history=fg_history + U, kappa=cfg.foolsgold_kappa,
                  weights=torch.tensor(sizes, dtype=torch.float32, device=dev))
        agg = aggregate(cfg.defence, U, **kw)
        mask = acceptance_mask(cfg.defence, U, **kw)
        set_flat_params(global_model, gp + agg)

        # trust instrumentation: the per-client weight a similarity rule assigned,
        # plus the geometry that explains it. This is the raw material for the
        # trust-trace question (scripts/trust_traces.py; "4b" in the pilot plan)
        # -- does projecting a batch onto the physics manifold raise its trust
        # while it still carries poison.
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

    # One threshold from the final model's clean-validation scores, applied to
    # every set. On the positives-only sets (test_targeted, test_untargeted)
    # only recall means anything: precision is 0 or 1, AUC-PR and best F1 are
    # NaN, and the delay treats the whole set as one attack segment.
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
