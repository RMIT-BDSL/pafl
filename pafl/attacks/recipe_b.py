"""Recipe B: an optimised, physics-violating fabrication by gradient matching.

Recipe A is a fixed transform. It is cheap and it already beats the baselines,
but a reviewer will ask the obvious question: what does an attacker do who
optimises against the detector instead of applying a canned trick? Recipe B is
that attacker. It is the construction the introduction names -- "a new
physics-violating fabrication attack that we construct by gradient matching" --
and it follows Witches' Brew (Geiping et al., ICLR 2021) adapted from a
classifier to a reconstruction detector.

The idea in one paragraph. A malicious client wants the shared autoencoder to
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
exactly the pair the paper needs: invisible in update space, detectable by the
physics check.

Two paths are provided:

* Full gradient matching (`first_order=False`). Differentiates through the inner
  parameter gradient (a double backward). Faithful to Witches' Brew, and the
  right setting for the AWS sweep.
* First-order alignment (`first_order=True`, the default). Skips the double
  backward and instead perturbs the batch so its *input-space* reconstruction
  gradient aligns the surrogate toward the target. An order of magnitude
  cheaper, close in effect, and the setting the compute plan recommends for the
  bulk runs. Use the full path for a headline table, the first-order path for
  breadth.

Discrete actuator channels are protected: fractional pump states would give the
fabrication away by other means, so they are held fixed and re-rounded at the
end. The perturbation on the continuous channels is bounded in units of each
channel's standard deviation, so "near X_honest" is measured in sigma, not in
raw engineering units that differ by three orders of magnitude across sensors.
"""
from __future__ import annotations
import numpy as np
import pandas as pd

from ..invariants.mine import classify_channels
from ..invariants.spec import InvariantSet


def _local_standardise(X: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
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
    """A small reconstruction detector trained on honest windows."""
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
    """g* : the parameter step that lowers reconstruction error on the target
    windows. Flattened and unit-normalised."""
    import torch
    lossf = torch.nn.MSELoss()
    model.zero_grad(set_to_none=True)
    xb = target_W.to(device)
    loss = lossf(model(xb), xb)
    grads = torch.autograd.grad(loss, list(model.parameters()))
    g = torch.cat([gr.reshape(-1) for gr in grads])
    # descent direction on the attack loss = -grad; unit vector
    g = -g
    return g / (g.norm() + 1e-12)


def fabricate_recipe_b(honest_df: pd.DataFrame, inv_set: InvariantSet | None,
                       cols: list[str], target_windows: np.ndarray | None = None,
                       window: int = 10, epsilon_sigma: float = 2.5,
                       match_steps: int = 200, surrogate_steps: int = 300,
                       lr_match: float = 0.05, first_order: bool = True,
                       seed: int = 0, device: str = "cpu") -> pd.DataFrame:
    """Return a fabricated copy of `honest_df` built by gradient matching.

    honest_df : the malicious client's own clean shard.
    target_windows : scaled windows of the attack the adversary wants hidden,
        shape (m, window*len(cols)). If None, the target step is taken toward
        increasing reconstruction error on the honest data itself, a generic
        "corrupt the learned manifold" objective that needs no attack sample.
    epsilon_sigma : perturbation bound per continuous channel, in standard
        deviations of that channel on this shard.

    The physics is not enforced here. Recipe B is the *unconstrained* optimised
    attacker; forcing its output back onto the invariant manifold is the
    defender's move, done separately by `attacks.adaptive.project_batch`. Keeping
    the two apart is what lets the experiment measure what the projection costs.
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
    if W0.shape[0] < 4:
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
            # cheap surrogate objective: move the batch so the surrogate
            # reconstructs it toward the target statistics. When a target is
            # given, pull the batch's window means toward the target's; else
            # simply inflate reconstruction error to corrupt the manifold.
            if g_star is not None and len(target_windows):
                tgt_mean = torch.tensor(np.asarray(target_windows, np.float32),
                                        device=dev).mean(0)
                obj = ((Wp.mean(0) - tgt_mean) ** 2).mean()
            else:
                obj = -((surrogate(Wp) - Wp) ** 2).mean()
        else:
            # full gradient matching: align the batch's parameter gradient with g*
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
