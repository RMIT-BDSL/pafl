"""The physics gate's verdict on every client batch of a federation.

Malicious verdicts give the "check admits" door of the results tables. Honest
verdicts are what substantiate the sentence "no honest client was rejected"
inside the federated runs themselves, on the very shards the detector trains
on, rather than only on the criterion-1 batches drawn from the same record
(criterion 1 is the pilot's name for the separation experiment,
scripts/separation.py, whose results are results/c1_*.json).

A batch is admitted when at most 1 % of its rows violate any invariant, the
default of `InvariantSet.batch_verdict`, which no federated run changes.
"""
from __future__ import annotations

import numpy as np


def client_verdicts(clients, inv_set) -> dict:
    """Run `inv_set.batch_verdict` on every client's raw batch.

    Returns the fields a scenario dict carries:
      physics_verdicts              one entry per client (client, is_malicious,
                                    violating_fraction, admitted)
      physics_admitted_rate         share of *malicious* batches admitted (None
                                    if there is no malicious client) -- the
                                    historical meaning of the field
      honest_physics_admitted_rate  share of honest batches admitted (None if
                                    there is no honest client)
      n_honest_rejected             honest clients the check would exclude
    """
    verdicts = []
    for c in clients:
        v = inv_set.batch_verdict(c.raw)
        verdicts.append({"client": int(c.client_id), "is_malicious": bool(c.is_malicious),
                         "violating_fraction": float(v["violating_fraction"]),
                         "admitted": bool(v["admitted"])})
    return summarise_verdicts(verdicts)


def summarise_verdicts(verdicts: list[dict]) -> dict:
    """The fields of `client_verdicts` from a list of per-client verdicts, so
    fl.variants can rebuild them after projecting or dropping clients."""
    mal = [v for v in verdicts if v.get("is_malicious", True)]
    hon = [v for v in verdicts if not v.get("is_malicious", True)]
    return {
        "physics_verdicts": verdicts,
        "physics_admitted_rate": float(np.mean([v["admitted"] for v in mal])) if mal else None,
        "honest_physics_admitted_rate": float(np.mean([v["admitted"] for v in hon])) if hon else None,
        "n_honest_rejected": int(sum(not v["admitted"] for v in hon)),
    }
