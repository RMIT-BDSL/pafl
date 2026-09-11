"""Robust aggregation rules, and the norm bound.

Every rule here takes a stack of client updates and returns one aggregate. That
is the point the paper makes: all of them reason about the update vector, and
none of them can see the data that produced it.

Shapes: updates is a tensor of shape (n_clients, n_params) holding deltas from
the current global model, not absolute weights.
"""
from __future__ import annotations
import torch


def fedavg(updates: torch.Tensor, weights: torch.Tensor | None = None, **kw) -> torch.Tensor:
    if weights is None:
        return updates.mean(dim=0)
    w = (weights / weights.sum()).to(device=updates.device, dtype=updates.dtype)
    return (updates * w[:, None]).sum(dim=0)


def krum(updates: torch.Tensor, n_malicious: int = 1, multi: int = 1, **kw) -> torch.Tensor:
    """Blanchard et al. Score each update by the distance to its closest
    neighbours, then keep the lowest-scoring one (or average the best `multi`)."""
    n = updates.shape[0]
    k = max(n - n_malicious - 2, 1)
    d = torch.cdist(updates, updates) ** 2
    d.fill_diagonal_(float("inf"))
    scores = torch.sort(d, dim=1).values[:, :k].sum(dim=1)
    idx = torch.argsort(scores)[:max(1, multi)]
    return updates[idx].mean(dim=0)


def coordinate_median(updates: torch.Tensor, **kw) -> torch.Tensor:
    return updates.median(dim=0).values


def trimmed_mean(updates: torch.Tensor, trim_frac: float = 0.2, **kw) -> torch.Tensor:
    n = updates.shape[0]
    k = int(n * trim_frac)
    if k == 0 or 2 * k >= n:
        return updates.mean(dim=0)
    s = updates.sort(dim=0).values
    return s[k:n - k].mean(dim=0)


def norm_clip(updates: torch.Tensor, clip: float | None = None, **kw) -> torch.Tensor:
    """Bound the magnitude of each update, then average.

    The honest observation the paper makes: this constrains size, not direction.
    """
    norms = updates.norm(dim=1, keepdim=True)
    if clip is None:
        clip = float(norms.median())
    scale = torch.clamp(clip / (norms + 1e-12), max=1.0)
    return (updates * scale).mean(dim=0)


def fltrust(updates: torch.Tensor, server_update: torch.Tensor | None = None, **kw) -> torch.Tensor:
    """Cao et al. Weight each client by cosine similarity to a server update
    computed on a small clean root dataset, clipped at zero, then rescale each
    client to the server's norm."""
    if server_update is None:
        return fedavg(updates)
    s = server_update
    sn = s.norm() + 1e-12
    cos = (updates @ s) / (updates.norm(dim=1) * sn + 1e-12)
    trust = torch.clamp(cos, min=0.0)
    if float(trust.sum()) <= 0:
        return torch.zeros_like(s)
    rescaled = updates * (sn / (updates.norm(dim=1, keepdim=True) + 1e-12))
    return (rescaled * trust[:, None]).sum(dim=0) / trust.sum()


def foolsgold(updates: torch.Tensor, history: torch.Tensor | None = None,
              kappa: float = 1.0, **kw) -> torch.Tensor:
    """Fung et al. (FoolsGold). Down-weight clients whose update directions are
    too similar to one another.

    The insight is that a group of sybils driving the model toward one shared
    goal produces updates that point the same way, round after round, more
    consistently than honest clients with genuinely different data do. FoolsGold
    measures the maximum pairwise cosine similarity of each client's history and
    turns a high similarity into a low weight. It keeps no root dataset, unlike
    FLTrust, which makes it the second similarity-based rule the paper needs for
    the FLTrust interaction: if forcing a batch onto the physics manifold raises
    its trust here too, the interaction is a property of similarity weighting,
    not of FLTrust alone.
    """
    w = foolsgold_weights(updates, history, kappa=kappa)
    return (updates * w[:, None]).sum(dim=0)


def foolsgold_weights(updates: torch.Tensor, history: torch.Tensor | None = None,
                      kappa: float = 1.0) -> torch.Tensor:
    """The per-client FoolsGold weights, in [0, 1]. Exposed for instrumentation."""
    H = history if history is not None else updates
    n = H.shape[0]
    if n < 2:
        return torch.ones(n, device=updates.device, dtype=updates.dtype)
    Hn = H / (H.norm(dim=1, keepdim=True) + 1e-12)
    cs = (Hn @ Hn.t()).clamp(-1.0, 1.0)
    cs.fill_diagonal_(0.0)
    v = cs.max(dim=1).values                      # each client's worst similarity
    # pardoning: a client more similar to others than they are to it keeps weight
    denom = v.clone()
    for i in range(n):
        for j in range(n):
            if v[j] > v[i] and v[j] > 1e-12:
                cs[i, j] *= v[i] / v[j]
    v = cs.max(dim=1).values
    a = 1.0 - v
    a = a / (a.max() + 1e-12)
    a = torch.clamp(a, 1e-6, 1.0)
    # logit re-scaling as in the paper, then renormalise to sum to 1
    a = kappa * (torch.log(a / (1 - a + 1e-12) + 1e-12) + 0.5)
    a = torch.clamp(a, 0.0, 1.0)
    if float(a.sum()) <= 0:
        return torch.ones(n, device=updates.device, dtype=updates.dtype) / n
    return a / a.sum()


def trust_weights(name: str, updates: torch.Tensor, **kw) -> torch.Tensor:
    """The per-client weight a similarity-based rule assigns this round.

    Returned for FLTrust and FoolsGold, the two rules whose weights the 4b
    experiment traces. For rules that select rather than weight, a 0/1 vector
    from the acceptance mask is returned, so every rule reports something
    comparable.
    """
    n = updates.shape[0]
    if name == "fltrust":
        s = kw.get("server_update")
        if s is None:
            return torch.ones(n, device=updates.device) / n
        cos = (updates @ s) / (updates.norm(dim=1) * (s.norm() + 1e-12) + 1e-12)
        trust = torch.clamp(cos, min=0.0)
        tot = float(trust.sum())
        return trust / tot if tot > 0 else torch.zeros(n, device=updates.device)
    if name == "foolsgold":
        return foolsgold_weights(updates, kw.get("history"), kappa=kw.get("kappa", 1.0))
    return acceptance_mask(name, updates, **kw).float()


DEFENCES = {
    "fedavg": fedavg,
    "krum": krum,
    "median": coordinate_median,
    "trimmed_mean": trimmed_mean,
    "norm_clip": norm_clip,
    "fltrust": fltrust,
    "foolsgold": foolsgold,
}


def aggregate(name: str, updates: torch.Tensor, **kw) -> torch.Tensor:
    if name not in DEFENCES:
        raise KeyError(f"unknown defence {name!r}; choose from {sorted(DEFENCES)}")
    return DEFENCES[name](updates, **kw)


def acceptance_mask(name: str, updates: torch.Tensor, **kw) -> torch.Tensor:
    """Which clients actually influenced the aggregate.

    Reported as the acceptance rate of malicious clients, which is one of the
    four go/no-go criteria. Rules that reweight rather than select report a
    client as accepted when its weight is materially above zero.
    """
    n = updates.shape[0]
    if name == "krum":
        n_mal = kw.get("n_malicious", 1)
        k = max(n - n_mal - 2, 1)
        d = torch.cdist(updates, updates) ** 2
        d.fill_diagonal_(float("inf"))
        scores = torch.sort(d, dim=1).values[:, :k].sum(dim=1)
        m = torch.zeros(n, dtype=torch.bool, device=updates.device)
        m[torch.argsort(scores)[:max(1, kw.get("multi", 1))]] = True
        return m
    if name == "trimmed_mean":
        trim = kw.get("trim_frac", 0.2)
        k = int(n * trim)
        if k == 0 or 2 * k >= n:
            return torch.ones(n, dtype=torch.bool, device=updates.device)
        norms = updates.norm(dim=1)
        order = torch.argsort(norms)
        m = torch.zeros(n, dtype=torch.bool, device=updates.device)
        m[order[k:n - k]] = True
        return m
    if name == "fltrust":
        s = kw.get("server_update")
        if s is None:
            return torch.ones(n, dtype=torch.bool, device=updates.device)
        cos = (updates @ s) / (updates.norm(dim=1) * (s.norm() + 1e-12) + 1e-12)
        return cos > 0.05
    if name == "foolsgold":
        w = foolsgold_weights(updates, kw.get("history"), kappa=kw.get("kappa", 1.0))
        return w > (0.5 / n)                       # materially above negligible
    return torch.ones(n, dtype=torch.bool, device=updates.device)      # fedavg, median, norm_clip use everyone
