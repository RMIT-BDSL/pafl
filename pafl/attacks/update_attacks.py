"""Update-space attack baselines.

Recipe A and Recipe B poison the *data*. The baselines here poison the *update*
directly, without touching any training data. They are the standard Byzantine
attacks the federated-learning literature is built on, and the paper includes
them for one reason: to show that the physics admission check is orthogonal to
them. A physics check reasons about the data behind an update. An update-space
attacker keeps its honest shard as the batch the check sees, so the check
admits it, and then submits a crafted vector that has nothing to do with that
batch. Binding the update to the batch is outside this paper's scope. The
*existing* robust-aggregation defences already handle several of these
attacks, whereas they do not handle the data fabrications. The two defence
families are therefore complementary, not competing.

The paper's four update-space baselines are `sign_flip` (sign flipping),
`scaling` (gradient scaling), `free_rider` (free riding) and `min_max`
(min-max). `additive_noise` and `alie` are implemented but appear in no
committed result. The drivers never set `update_attack_kw`, so every run used
the defaults below: sign_flip scale 1, scaling factor 10, free_rider jitter
0.01 with seed 0, and min_max starting step 5
(results/swat_sweep_wide_3seed.json).

pafl/fl/train.py calls these every round, after local training, once per
malicious client. `updates` is that round's full stack of client updates and
`honest_mask` marks the honest rows. The attacker therefore knows every honest
update of the round, the full-knowledge setting of Shejwalkar and Houmansadr.
Every function here is deterministic given its inputs.

A note on "label flipping". For a supervised classifier, label flipping inverts
the training labels. This detector is an unsupervised reconstruction
autoencoder, which never reads a label, so a literal label flip is a no-op. Its
faithful analogue is the targeted data objective already implemented in the
scenario builders: present attack windows to the local trainer as normal, so the
shared model learns to reconstruct them. The paper reports that analogue as
"historical attack replay" (`splice_only`), not as label flipping, and it lives
with the data poisoning, not here.

Each function maps one honest update to a malicious one. Some need the honest
update population to stay within its variance (ALIE / min-max), so every
function receives the full update stack and the honest mask. Extra keyword
arguments are swallowed by `**kw`, so a misspelt parameter is silently ignored.
"""
from __future__ import annotations
import numpy as np


def _torch():
    import torch
    return torch


def sign_flip(update, updates, honest_mask, scale: float = 1.0, **kw):
    """Negate the update (optionally amplified). Pulls the model the wrong way.

    The client's own honest update, times -scale. At the paper's scale 1 the
    norm is an honest one, so a norm bound cannot see it; direction- and
    distance-based rules can. scale > 1 is the stronger, louder version."""
    return -scale * update


def scaling(update, updates, honest_mask, factor: float = 10.0, **kw):
    """Boost the update magnitude. The classic model-replacement lever; caught
    by norm bounds, which is exactly what makes it a useful contrast.

    The client's own honest update times `factor` (10 in the paper runs). A
    smaller factor is harder to catch and does less damage."""
    return factor * update


def additive_noise(update, updates, honest_mask, sigma: float = 1.0, seed: int = 0, **kw):
    """Add Gaussian noise scaled to the honest update spread.

    The noise sd is `sigma` times the standard deviation of all entries of
    the honest updates, one scalar. Not used in any committed result."""
    torch = _torch()
    g = torch.Generator(device="cpu").manual_seed(seed)
    hon = updates[honest_mask]
    scale = float(hon.std()) if hon.numel() else 1.0
    noise = torch.randn(update.shape, generator=g).to(update.device) * (sigma * scale)
    return update + noise


def free_rider(update, updates, honest_mask, jitter: float = 0.01, seed: int = 0, **kw):
    """Contribute nothing but a little noise, to look like a participant while
    coasting on everyone else's work.

    The update is Gaussian noise with sd = `jitter` (0.01 in the paper runs)
    times the standard deviation of all honest update entries. The generator
    is reseeded with `seed` on every call. With the default seed 0, every
    malicious client submits the same direction in every round, and only the
    scale follows the honest spread. That makes the free riders identical to
    one another, which similarity rules such as FoolsGold are built to spot.
    A stealthier free rider would send a stale copy of the global update; a
    weaker one would send zeros."""
    torch = _torch()
    g = torch.Generator(device="cpu").manual_seed(seed)
    scale = float(updates[honest_mask].std()) if updates[honest_mask].numel() else 1.0
    return torch.randn(update.shape, generator=g).to(update.device) * (jitter * scale)


def alie(update, updates, honest_mask, z: float = 1.5, **kw):
    """A Little Is Enough (Baruch et al.). Shift along the honest mean by a few
    standard deviations -- far enough to move the model, near enough to stay
    inside the honest cloud a distance filter tolerates.

    Coordinate-wise mu - z * sd over the honest updates. z is fixed at 1.5
    here rather than derived from the client counts as in the paper. Not
    used in any committed result."""
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
    a bisection on the step size, which is the standard construction.

    The perturbation is their "inverse unit vector", -mu/|mu|. `step` = 5 is
    only the first bracket: it is doubled until the constraint fails (at most
    20 times), then bisected 20 times. So the result does not depend on it
    unless the honest spread is enormous. The client's own update is ignored,
    and every malicious client submits the same vector. Their inverse-sign and
    inverse-std directions, or a rule-specific optimisation, would be stronger
    versions."""
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
    """Dispatch by name; `kw` is the client's `update_attack_kw`."""
    if name not in UPDATE_ATTACKS:
        raise KeyError(f"unknown update attack {name!r}; choose from {sorted(UPDATE_ATTACKS)}")
    return UPDATE_ATTACKS[name](update, updates, honest_mask, **kw)
