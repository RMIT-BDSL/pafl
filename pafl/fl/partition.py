"""Turn one real plant record into a federation of clients.

The synthetic scenario has many plants by construction: it simulates each site
with its own set points. A real testbed such as SWaT is one plant, recorded
once. To study cross-operator federated learning on it we must split that one
record into several clients, and the split is not a detail -- it decides whether
the experiment tests the thing the paper claims. Each client's piece is its
"shard", the paper's word for one client's partition of the record.

Two ways to split. The paper uses temporal shards throughout; the IID split is
implemented as a contrast, and no committed result uses it.

* Temporal shards (default). Cut the normal record into contiguous blocks and
  give one block to each client. Because a water plant drifts through operating
  regimes over hours -- different tank levels, different duty cycles -- adjacent
  blocks are not identical draws. This produces a mild, realistic non-IID split:
  every client sees the same plant but a different slice of its behaviour. This
  is the honest analogue of "different operators running similar plants".

* IID shuffle. Shuffle all rows, then deal them out. Every client sees the same
  distribution. Robust aggregation was designed for exactly this case, so it is
  the easy setting for the baselines and the wrong one for the paper's argument.
  It is kept only as a contrast, to show how much the baselines rely on the
  clustering assumption that a real federation violates.

This module only splits. What a malicious client then does to its own shard --
splice in real attack rows, fabricate on top with the Recipe A or Recipe B
machinery the synthetic scenario uses -- happens in fl.scenario_real, so the
physics is broken on data drawn from the real plant, not on a simulation.
"""
from __future__ import annotations
from dataclasses import dataclass
import numpy as np
import pandas as pd


@dataclass
class PartitionConfig:
    """How to split the client pool. fl.scenario_real fills n_clients, scheme and
    seed from its own config and leaves the rest at these defaults."""
    n_clients: int = 10
    scheme: str = "temporal"        # temporal | iid
    contiguous_block: bool = True   # not read anywhere: temporal shards are always contiguous
    seed: int = 0                   # iid only; the temporal split is deterministic
    # Refuse a split thinner than this. It is why BATADAL runs with 5 clients:
    # its client pool of 4,381 hourly rows would give 438 rows each at 10.
    min_rows_per_client: int = 500


def partition_frame(normal: pd.DataFrame, cfg: PartitionConfig) -> list[pd.DataFrame]:
    """Split one clean dataframe into `n_clients` client frames.

    `normal` must be attack-free (ATT_FLAG all zero or absent); a client trains
    only on data it believes is normal. The attack file is never partitioned --
    it is the shared held-out test set, the same for every client. In
    fl.scenario_real, `normal` is the client pool: the half of the normal
    record left after the invariant, validation and root slices are carved off.
    """
    if "ATT_FLAG" in normal.columns and int(normal["ATT_FLAG"].sum()) > 0:
        raise ValueError("partition_frame expects an attack-free frame; pass the "
                         "normal record, keep the attack file for the test set")
    n = len(normal)
    k = cfg.n_clients
    if n < k * cfg.min_rows_per_client:
        raise ValueError(f"{n} rows is too few for {k} clients at "
                         f"{cfg.min_rows_per_client} rows each")

    if cfg.scheme == "temporal":
        # contiguous, near-equal blocks preserving time order within each client;
        # sizes differ by at most one row, and client i holds the i-th block
        edges = np.linspace(0, n, k + 1).astype(int)
        return [normal.iloc[edges[i]:edges[i + 1]].reset_index(drop=True)
                for i in range(k)]

    if cfg.scheme == "iid":
        # Rows are dealt at random and then put back in time order, so an IID
        # shard is not contiguous: a window cut from it spans gaps in time.
        rs = np.random.default_rng(cfg.seed)
        order = rs.permutation(n)
        shards = np.array_split(order, k)
        return [normal.iloc[np.sort(s)].reset_index(drop=True) for s in shards]

    raise ValueError(f"unknown partition scheme {cfg.scheme!r}; choose temporal or iid")
