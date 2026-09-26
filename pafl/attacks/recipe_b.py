"""Recipe B: an optimised, physics-violating perturbation (the paper's "optimised perturbation").

Recipe A is a fixed transform. Recipe B is the attacker who optimises against a
surrogate of the detector instead of applying a canned trick. The paper runs it
in its untargeted form: an error-maximising perturbation, in the manner of the
adversarial poisons of Fowl et al. (NeurIPS 2021). The module also holds a
gradient-matching path after Witches' Brew (Geiping et al., ICLR 2021),
adapted from a classifier to a reconstruction detector; no paper run uses it.

What the committed results actually ran. Both scenario builders call
`fabricate_recipe_b(batch, inv_set, cols, window=..., seed=...)`, with no
`target_windows` and the default `first_order=True`. So the `recipe_b` cells
of results/swat_sweep_wide_3seed.json used the untargeted objective described
under `fabricate_recipe_b`. That objective raises the surrogate's
reconstruction error inside a +/-2.5 sigma box. No gradient is matched. The
gradient-matching path below exists and is exercised only by
tests/test_week2.py.

The design, which the full path implements. A malicious client wants the shared autoencoder to
reconstruct a target attack well, so that the attack stops looking anomalous.
The cleanest way to move the shared model in that direction is one gradient
step that reduces the reconstruction error on the target windows; call that
target step g*. The attacker cannot submit g* directly -- a robust rule may
reject it -- but it can craft a *training batch* whose own gradient points the
same way, and submit the honest-looking update that batch induces. So the
attacker solves

    max_X  cos( grad_theta L(theta*, X) ,  g* )   subject to  X near X_honest,

where theta* is a surrogate detector trained on honest data. Because the batch
matches the attack's gradient rather than copying the attack, the update sits
inside the benign cloud, and because matching that gradient distorts the
relations between channels, the batch violates the plant's physics. That is
the intended pair: invisible in update space, detectable by the physics
check.

Two paths are provided:

* Full gradient matching (`first_order=False`). Differentiates through the
  inner parameter gradient (a double backward) and maximises the cosine
  between the batch's parameter gradient and g*. Faithful to Witches' Brew.
  It needs `target_windows`, because g* is undefined without them.
* First-order (`first_order=True`, the default). No double backward and no
  gradient alignment. With targets it pulls the mean of the batch's windows
  toward the mean target window, a feature-matching proxy. Without targets it
  maximises the surrogate's reconstruction error on the batch, an untargeted
  "corrupt the learned manifold" objective. It is much cheaper than the full
  path, because it builds no second-order graph.

Discrete actuator channels are protected, because fractional pump states would
give the fabrication away by other means. The perturbation is masked to the
continuous channels, and the discrete columns are copied from the input
unchanged. The perturbation is bounded in units of each channel's standard
deviation on this shard, so "near X_honest" is measured in sigma, not in raw
engineering units that differ by three orders of magnitude across sensors.

Nothing here enforces the physics. Recipe B's output is submitted as is, the
naive attacker. Moving it onto the invariants is the physics-aware attacker's
separate step, `attacks.adaptive.project_batch`. No committed adaptive result
applies that step to Recipe B.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

from ..invariants.mine import classify_channels
from ..invariants.spec import InvariantSet


def _local_standardise(X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    # the shard's own mean and sd, not the federation's Scaler: the attacker
    # works from its own data only
    mu = X.mean(0)
    sd = X.std(0) + 1e-8
    return (X - mu) / sd, mu, sd


def _unfold_windows(Xt, window: int):
    """Differentiable windowing: raw rows [n, C] -> windows [n-w+1, w*C]."""
    import torch
    n, c = Xt.shape
    if n < window:
        return Xt.reshape(1, -1)[:0]
    idx = torch.arange(n - window + 1).unsqueeze(1) + torch.arange(window).unsqueeze(0)
    return Xt[idx].reshape(n - window + 1, window * c)


def _train_surrogate(Wt, window: int, c: int, steps: int, lr: float, seed: int, device: str):
    """A small reconstruction detector trained on honest windows.

    The same architecture as the federated detector (WindowAE), trained once
    from scratch on this shard before the federation starts. The attacker
    never sees the global model. A stronger attacker would re-craft its batch
    every round against the current global weights. torch.manual_seed resets
    the global torch RNG here, and run_federation reseeds before training, so
    the side effect does not reach the federated results."""
    import torch
    from ..fl.models import WindowAE
    torch.manual_seed(seed)
    model = WindowAE(n_channels=c, window=window).to(device)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    lossf = torch.nn.MSELoss()
    model.train()
    n = Wt.shape[0]
    bs = min(256, n)
    for _ in range(steps):
        idx = torch.randint(0, n, (bs,), device=device)
        opt.zero_grad()
        xb = Wt[idx]
        loss = lossf(model(xb), xb)
        loss.backward()
        opt.step()
    model.eval()
    return model


def _target_gradient(model, target_W, device):
    """g* : the gradient of the reconstruction loss on the target windows with
    respect to the surrogate's parameters, flattened and unit-normalised.

    It is the gradient itself, not its negative. Training descends the batch's
    loss, so a batch whose gradient points along g* makes each training step a
    descent step on the target's loss as well, which is Witches' Brew's
    alignment. Until 26 Sep 2026 this returned -g, so the matching step pushed
    the target's error up; no committed result used this path."""
    import torch
    lossf = torch.nn.MSELoss()
    model.zero_grad(set_to_none=True)
    xb = target_W.to(device)
    loss = lossf(model(xb), xb)
    grads = torch.autograd.grad(loss, list(model.parameters()))
    g = torch.cat([gr.reshape(-1) for gr in grads])
    return g / (g.norm() + 1e-12)


def fabricate_recipe_b(honest_df: pd.DataFrame, inv_set: InvariantSet | None,
                       cols: list[str], target_windows: np.ndarray | None = None,
                       window: int = 10, epsilon_sigma: float = 2.5,
                       match_steps: int = 200, surrogate_steps: int = 300,
                       lr_match: float = 0.05, first_order: bool = True,
                       seed: int = 0, device: str = "cpu") -> pd.DataFrame:
    """Return a fabricated copy of `honest_df`, perturbed on its continuous channels.

    honest_df : the malicious client's shard. In the federated runs this is
        the shard with the target attack segments already spliced in.
    inv_set : accepted so Recipe A and B share one dispatch signature; unused.
    target_windows : windows of the attack the adversary wants hidden, shape
        (m, window*len(cols)). They must be in this shard's local z-units (the
        mean and sd `_local_standardise` computes), because both objectives
        compare them with the standardised batch. Those statistics are not
        returned, so a caller has to recompute them. If None, the objective
        maximises the surrogate's reconstruction error on the batch, an
        untargeted objective that needs no attack sample. Every committed
        result used None.
    epsilon_sigma : L-infinity bound on the perturbation per continuous
        channel, in standard deviations of that channel on this shard.

    Every committed run used the defaults: window 10, epsilon_sigma 2.5,
    match_steps 200 Adam steps at lr_match 0.05, surrogate_steps 300, and the
    first-order path. The attacker's strength is the box and the step budget.
    A larger epsilon_sigma or more match steps moves the batch further, which
    means more poison and more violations. A smaller box is closer to honest
    and harder to catch, but it carries less poison. The output has ATT_FLAG
    set to 0, and its row index is reset.
    """
    import torch

    out = honest_df.copy().reset_index(drop=True)
    cont, disc = classify_channels(honest_df)
    cont_cols = [c for c in cols if c in cont]
    if not cont_cols:
        return out

    X = out[cols].to_numpy(np.float64)
    col_idx = {c: i for i, c in enumerate(cols)}
    cont_j = np.array([col_idx[c] for c in cont_cols], dtype=int)

    Xs, mu, sd = _local_standardise(X)
    c = len(cols)
    dev = torch.device(device)
    torch.manual_seed(seed)

    Xs_t = torch.tensor(Xs, dtype=torch.float32, device=dev)
    W0 = _unfold_windows(Xs_t, window)
    if W0.shape[0] < 4:          # too few windows to train a surrogate: return the shard unchanged
        return out

    surrogate = _train_surrogate(W0.detach(), window, c, surrogate_steps,
                                 lr=1e-3, seed=seed, device=dev)
    for p in surrogate.parameters():
        p.requires_grad_(False)

    # target step g*
    if target_windows is not None and len(target_windows):
        tW = torch.tensor(np.asarray(target_windows, np.float32), device=dev)
        for p in surrogate.parameters():
            p.requires_grad_(True)
        g_star = _target_gradient(surrogate, tW, dev).detach()
        for p in surrogate.parameters():
            p.requires_grad_(False)
    else:
        g_star = None

    # perturbation on continuous channels only, bounded in sigma units
    mask = torch.zeros(c, device=dev)
    mask[torch.tensor(cont_j, device=dev)] = 1.0
    delta = torch.zeros_like(Xs_t, requires_grad=True)
    opt = torch.optim.Adam([delta], lr=lr_match)
    lossf = torch.nn.MSELoss()

    for _ in range(match_steps):
        opt.zero_grad()
        Xp = Xs_t + delta * mask
        Wp = _unfold_windows(Xp, window)

        if first_order:
            # No gradient alignment on this path. With a target, pull the
            # batch's mean window toward the target's mean window (g_star is
            # only a flag here). Without one, the branch every committed run
            # took, inflate the surrogate's reconstruction error to corrupt
            # the manifold it learns.
            if g_star is not None and len(target_windows):
                tgt_mean = torch.tensor(np.asarray(target_windows, np.float32),
                                        device=dev).mean(0)
                obj = ((Wp.mean(0) - tgt_mean) ** 2).mean()
            else:
                obj = -((surrogate(Wp) - Wp) ** 2).mean()
        else:
            # full gradient matching: align the batch's parameter gradient with g*.
            # Both are gradients of a reconstruction loss (batch and target), so
            # a training step on this batch also lowers the target's error.
            for p in surrogate.parameters():
                p.requires_grad_(True)
            rec = lossf(surrogate(Wp), Wp)
            grads = torch.autograd.grad(rec, list(surrogate.parameters()),
                                        create_graph=True)
            g = torch.cat([gr.reshape(-1) for gr in grads])
            g = g / (g.norm() + 1e-12)
            obj = -(g * g_star).sum()          # maximise cosine -> minimise -cos
            for p in surrogate.parameters():
                p.requires_grad_(False)

        obj.backward()
        opt.step()
        with torch.no_grad():
            # project back into the sigma box after every step
            delta.clamp_(-epsilon_sigma, epsilon_sigma)
            delta.mul_(mask)

    with torch.no_grad():
        Xp = (Xs_t + delta * mask).cpu().numpy().astype(np.float64)

    # de-standardise the continuous channels; leave discrete channels untouched
    Xnew = X.copy()
    for k, j in enumerate(cont_j):
        Xnew[:, j] = Xp[:, j] * sd[j] + mu[j]

    for i, cname in enumerate(cols):
        out[cname] = Xnew[:, i]
    if "ATT_FLAG" in out.columns:
        out["ATT_FLAG"] = 0
    return out
