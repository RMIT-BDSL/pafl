"""The seven aggregation rules the paper compares.

Every rule here takes a stack of client updates and returns one aggregate. That
is the point the paper makes: all of them reason about the update vector, and
none of them can see the data that produced it.

Shapes: updates is a tensor of shape (n_clients, n_params) holding deltas from
the current global model, not absolute weights. fl.train adds the aggregate to
the global model unscaled (a server learning rate of 1).

Hyperparameters as the paper's runs use them. Each is the FLConfig default in
fl.train, which fills the keyword arguments below, and no script overrides one:

  fedavg        weighted by each client's number of training windows. Shards are
                equal to within one row, so in practice this is the plain mean.
  krum          f = the true number of malicious clients in the federation, at
                least 1 (fl.train passes it); k = n - f - 2 neighbours; multi = 1,
                so classic Krum: one update is selected.
  median        coordinate-wise; the lower median when n is even (see below).
  trimmed_mean  trim_frac = 0.2: with 10 clients, the 2 largest and 2 smallest
                values of every coordinate are dropped.
  norm_clip     clip = None: the bound is the median update norm of the round.
  fltrust       the server update is trained on the root set with the clients'
                own local-training settings. The root set is a clean slice of the
                normal record, root_fraction = 0.05 in fl.scenario_real (SWaT:
                4,734 rows at the 5 s stride, the same size as one client's
                shard); 800 simulated steps on the synthetic plant (fl.scenario).
  foolsgold     kappa = 1.0; the history is each client's running sum of its
                updates, current round included.

Sources: Krum, Blanchard et al. 2017; median and trimmed mean, Yin et al. 2018;
the norm bound, Sun et al. 2019; FLTrust, Cao et al. 2021; FoolsGold, Fung et
al. 2020.
"""
from __future__ import annotations
import torch


def fedavg(updates: torch.Tensor, weights: torch.Tensor | None = None, **kw) -> torch.Tensor:
    """The mean update, weighted by client data size when `weights` is given.

    fl.train passes each client's number of training windows as the weight.
    FLTrust falls back to this rule when there is no server update.
    """
    if weights is None:
        return updates.mean(dim=0)
    w = (weights / weights.sum()).to(device=updates.device, dtype=updates.dtype)
    return (updates * w[:, None]).sum(dim=0)


def krum(updates: torch.Tensor, n_malicious: int = 1, multi: int = 1, **kw) -> torch.Tensor:
    """Blanchard et al. Score each update by the distance to its closest
    neighbours, then keep the lowest-scoring one (or average the best `multi`).

    `n_malicious` is Krum's f, the number of Byzantine clients it is told to
    expect. fl.train sets it to the true count (at least 1), so Krum runs with
    f = 3 in an attacked federation of 10, f = 1 in the clean and honest-only
    ones, and in a gated one with however many malicious clients the gate let
    through.
    """
    n = updates.shape[0]
    k = max(n - n_malicious - 2, 1)     # neighbours scored: n - f - 2, as in Blanchard et al.
    d = torch.cdist(updates, updates) ** 2          # squared Euclidean distance
    d.fill_diagonal_(float("inf"))
    scores = torch.sort(d, dim=1).values[:, :k].sum(dim=1)
    idx = torch.argsort(scores)[:max(1, multi)]
    return updates[idx].mean(dim=0)


def coordinate_median(updates: torch.Tensor, **kw) -> torch.Tensor:
    """Yin et al. The median of every coordinate taken separately.

    torch.median returns the lower middle value for an even count (10 clients:
    the 5th smallest), where the textbook median averages the two middle values.
    """
    return updates.median(dim=0).values


def trimmed_mean(updates: torch.Tensor, trim_frac: float = 0.2, **kw) -> torch.Tensor:
    """Yin et al. Per coordinate, drop the int(n * trim_frac) largest and smallest
    values and average the rest.

    With the default 0.2 and 10 clients, 2 values are trimmed from each end, fewer
    than the 3 malicious clients the paper's federation holds. In a federation
    too small to trim anything (k = 0 or 2k >= n) this falls back to the mean.
    """
    n = updates.shape[0]
    k = int(n * trim_frac)
    if k == 0 or 2 * k >= n:
        return updates.mean(dim=0)
    s = updates.sort(dim=0).values
    return s[k:n - k].mean(dim=0)


def norm_clip(updates: torch.Tensor, clip: float | None = None, **kw) -> torch.Tensor:
    """Bound the magnitude of each update, then average (unweighted).

    The honest observation the paper makes: this constrains size, not direction.

    The norm bound follows Sun et al. With `clip` None (the FLConfig default,
    and what every paper run uses) the bound is the median L2 norm of this
    round's updates, so no absolute scale has to be set per dataset, and at
    most half the clients are scaled down in any round.
    """
    norms = updates.norm(dim=1, keepdim=True)
    if clip is None:
        clip = float(norms.median())
    scale = torch.clamp(clip / (norms + 1e-12), max=1.0)
    return (updates * scale).mean(dim=0)


def fltrust(updates: torch.Tensor, server_update: torch.Tensor | None = None, **kw) -> torch.Tensor:
    """Cao et al. Weight each client by cosine similarity to a server update
    computed on a small clean root dataset, clipped at zero, then rescale each
    client to the server's norm.

    fl.train computes `server_update` each round by training a copy of the
    global model on `root_data` with the clients' settings (local epochs, Adam
    learning rate, mini-batch size). The root set is not small here: on the real
    records it is as large as one client's shard (see the module docstring).
    """
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
    not of FLTrust alone. (On the real records that interaction did not appear,
    and the paper reports it as an observation; scripts/trust_traces.py
    measures it.)

    The aggregate is the weighted sum of this round's updates, with weights that
    sum to 1; the similarity is measured on `history`, not on this round alone.
    """
    w = foolsgold_weights(updates, history, kappa=kappa)
    return (updates * w[:, None]).sum(dim=0)


def foolsgold_weights(updates: torch.Tensor, history: torch.Tensor | None = None,
                      kappa: float = 1.0) -> torch.Tensor:
    """The per-client FoolsGold weights, in [0, 1] and summing to 1. Exposed for
    instrumentation.

    The steps of Fung et al.'s algorithm: pairwise cosine similarity of the
    clients' histories, pardoning, 1 - max similarity, rescale so the most
    distinct client gets 1, then the logit with confidence kappa, clipped to
    [0, 1]. The optional feature-importance weighting of the original is not
    implemented. `history` defaults to this round's updates.
    """
    H = history if history is not None else updates
    n = H.shape[0]
    if n < 2:
        return torch.ones(n, device=updates.device, dtype=updates.dtype)
    Hn = H / (H.norm(dim=1, keepdim=True) + 1e-12)
    cs = (Hn @ Hn.t()).clamp(-1.0, 1.0)
    cs.fill_diagonal_(0.0)
    v = cs.max(dim=1).values                      # each client's worst similarity
    # pardoning: a client more similar to others than they are to it keeps weight
    denom = v.clone()                             # unused
    for i in range(n):
        for j in range(n):
            if v[j] > v[i] and v[j] > 1e-12:
                cs[i, j] *= v[i] / v[j]
    v = cs.max(dim=1).values
    a = 1.0 - v
    a = a / (a.max() + 1e-12)
    a = torch.clamp(a, 1e-6, 1.0)
    # logit re-scaling as in the paper, then renormalise to sum to 1. The 1e-12
    # guards stand in for the original's "set a weight of exactly 1 to 0.99":
    # the most distinct client's logit is large and the clip below takes it to 1.
    a = kappa * (torch.log(a / (1 - a + 1e-12) + 1e-12) + 0.5)
    a = torch.clamp(a, 0.0, 1.0)
    if float(a.sum()) <= 0:
        return torch.ones(n, device=updates.device, dtype=updates.dtype) / n
    return a / a.sum()


def trust_weights(name: str, updates: torch.Tensor, **kw) -> torch.Tensor:
    """The per-client weight a similarity-based rule assigns this round.

    Returned for FLTrust and FoolsGold, the two rules whose weights the trust
    traces follow (scripts/trust_traces.py; "4b" was the pilot plan's name for
    that experiment, and survives in older file names). For FLTrust it is
    the normalised ReLU-cosine trust, before each update is rescaled to the
    server's norm. For rules that select rather than weight, a 0/1 vector from
    the acceptance mask is returned, so every rule reports something comparable.
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
    """Apply the rule `name`. Every rule takes the full keyword set fl.train
    builds and ignores the arguments it does not use."""
    if name not in DEFENCES:
        raise KeyError(f"unknown defence {name!r}; choose from {sorted(DEFENCES)}")
    return DEFENCES[name](updates, **kw)


def acceptance_mask(name: str, updates: torch.Tensor, **kw) -> torch.Tensor:
    """Which clients actually influenced the aggregate.

    fl.train averages the malicious entries over rounds into
    `malicious_acceptance_rate`, the "rule admits" column of the results tables
    (the physics check's verdict is the other door; see fl.gate). It was one of
    the pilot's four go/no-go criteria. Rules that reweight rather than select
    report a client as accepted when its weight is materially above zero; the
    cut-offs below are reporting conventions, not part of the rules:

      krum          the selected update(s), recomputed exactly as in `krum`
      trimmed_mean  a proxy: the rule trims per coordinate, so no client is
                    ever wholly dropped; a client counts as accepted when its
                    update norm is outside the k largest and k smallest
      fltrust       cosine to the server update above 0.05
      foolsgold     weight above half of an equal share, 0.5 / n
      others        everyone (fedavg, median, norm_clip)
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
