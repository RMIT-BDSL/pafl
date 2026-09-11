"""Update-space attack baselines.

Recipe A and Recipe B poison the *data*. The baselines here poison the *update*
directly, without touching any training data. They are the standard Byzantine
attacks the federated-learning literature is built on, and the paper includes
them for one reason: to show that the physics admission check is orthogonal to
them. A physics check reasons about the data behind an update; an update-space
attack submits a crafted vector with no honest data behind it at all, so the
check has nothing to attest and these attacks pass it by construction. The point
the paper makes is that the *existing* robust-aggregation defences already
handle several of these, whereas they do not handle the data fabrications -- and
that the two defence families are therefore complementary, not competing.

A note on "label flipping". For a supervised classifier, label flipping inverts
the training labels. This detector is an unsupervised reconstruction
autoencoder, which never reads a label, so a literal label flip is a no-op. Its
faithful analogue is the targeted data objective already implemented in the
scenario builders: present attack windows to the local trainer as normal, so the
shared model learns to reconstruct them. That analogue is reported under the
"label flipping" name in the paper, and lives with the data poisoning, not here.

Each function maps one honest update to a malicious one. Some need the honest
update population to stay within its variance (ALIE / min-max), so every
function receives the full update stack and the honest mask.
"""
from __future__ import annotations
import numpy as np


def _torch():
    import torch
    return torch


def sign_flip(update, updates, honest_mask, scale: float = 1.0, **kw):
    """Negate the update (optionally amplified). Pulls the model the wrong way."""
    return -scale * update


def scaling(update, updates, honest_mask, factor: float = 10.0, **kw):
    """Boost the update magnitude. The classic model-replacement lever; caught
    by norm bounds, which is exactly what makes it a useful contrast."""
    return factor * update


def additive_noise(update, updates, honest_mask, sigma: float = 1.0, seed: int = 0, **kw):
    """Add Gaussian noise scaled to the honest update spread."""
    torch = _torch()
    g = torch.Generator(device="cpu").manual_seed(seed)
    hon = updates[honest_mask]
    scale = float(hon.std()) if hon.numel() else 1.0
    noise = torch.randn(update.shape, generator=g).to(update.device) * (sigma * scale)
    return update + noise


def free_rider(update, updates, honest_mask, jitter: float = 0.01, seed: int = 0, **kw):
    """Contribute nothing but a little noise, to look like a participant while
    coasting on everyone else's work."""
    torch = _torch()
    g = torch.Generator(device="cpu").manual_seed(seed)
    scale = float(updates[honest_mask].std()) if updates[honest_mask].numel() else 1.0
    return torch.randn(update.shape, generator=g).to(update.device) * (jitter * scale)


def alie(update, updates, honest_mask, z: float = 1.5, **kw):
    """A Little Is Enough (Baruch et al.). Shift along the honest mean by a few
    standard deviations -- far enough to move the model, near enough to stay
    inside the honest cloud a distance filter tolerates."""
    hon = updates[honest_mask]
    if hon.shape[0] < 2:
        return update
    mu = hon.mean(0)
    sd = hon.std(0)
    return mu - z * sd


def min_max(update, updates, honest_mask, step: float = 5.0, **kw):
    """Shejwalkar-Houmansadr min-max: perturb the honest mean along the negative
    mean direction as far as the update can while its distance to the farthest
    honest update stays below the max honest-to-honest distance. Solved here by
    a bisection on the step size, which is the standard construction."""
    torch = _torch()
    hon = updates[honest_mask]
    if hon.shape[0] < 2:
        return update
    mu = hon.mean(0)
    pert = mu / (mu.norm() + 1e-12)
    # max pairwise honest distance sets the budget
    d = torch.cdist(hon, hon)
    budget = float(d.max())
    lo, hi = 0.0, step
    # grow hi until it violates, then bisect
    for _ in range(20):
        cand = mu - hi * pert
        if float(torch.cdist(cand.unsqueeze(0), hon).max()) > budget:
            break
        hi *= 2
    for _ in range(20):
        mid = 0.5 * (lo + hi)
        cand = mu - mid * pert
        if float(torch.cdist(cand.unsqueeze(0), hon).max()) <= budget:
            lo = mid
        else:
            hi = mid
    return mu - lo * pert


UPDATE_ATTACKS = {
    "sign_flip": sign_flip,
    "scaling": scaling,
    "additive_noise": additive_noise,
    "free_rider": free_rider,
    "alie": alie,
    "min_max": min_max,
}


def apply_update_attack(name: str, update, updates, honest_mask, **kw):
    if name not in UPDATE_ATTACKS:
        raise KeyError(f"unknown update attack {name!r}; choose from {sorted(UPDATE_ATTACKS)}")
    return UPDATE_ATTACKS[name](update, updates, honest_mask, **kw)
