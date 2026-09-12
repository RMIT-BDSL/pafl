"""Build the three federations the adaptive-attacker experiments compare.

    clean       every client honest                        -- the reference
    fabricated  malicious clients train on Recipe A/B data -- caught by the check
    projected   the same clients project first             -- passes the check

One construction for the simulated plant and for a real record, used by
day45_adaptive.py (every aggregation rule) and week2_4b.py (the similarity
rules, with trust traces), so the two scripts cannot drift apart.

The projected variant must differ from the fabricated one in exactly one way:
the batch has been moved onto the physics manifold. The pilot's first version
also, by accident, dropped the malicious client's oversampling of attack
windows when it rebuilt the training set from the projected batch, so the
"projected" attacker was weaker for a reason that had nothing to do with
physics. `ClientData.train_index` now carries the selection, and it is applied
here after re-windowing.
"""
from __future__ import annotations
import time

import numpy as np

from ..attacks.adaptive import project_batch, projection_cost
from ..data.loaders import make_windows
from ..invariants.mine import classify_channels
from ..utils.logging import get_logger
from .gate import client_verdicts, summarise_verdicts

log = get_logger("pafl.variants")

MODES = ("clean", "honest_only", "fabricated", "projected", "gated")
# honest_only = the fabricated federation with its malicious clients simply
# absent: the same seven honest shards, no attacker. It is the fair reference
# for the attacked runs (the "clean" run has ten honest shards, so a rule that
# selects a single client, such as Krum, can differ from it for reasons that
# are composition, not poisoning), and it is what "gated" becomes when the gate
# excludes every malicious client.
# gated = the deployed system: the attacker projects, the server runs the check,
# and a malicious client whose batch still fails it is excluded from the round.
# "projected" keeps every client in, so it measures what the projection alone
# does to the poison; "gated" measures what the gate does to the federation.


def build_variant(dataset: str, mode: str, malicious_fraction: float, n_clients: int,
                  window: int, seed: int, *, data_dir: str | None = None,
                  partition: str = "temporal", fabrication: str = "channel_roll",
                  roll_shift: int | None = None, invariant_kw: dict | None = None,
                  target_attack_fraction: float | None = None,
                  steps_per_client: int = 4000, protect_status: bool = True,
                  target_violating: float = 0.005, proj_stats: list | None = None):
    """Return (scenario, invariant_set, feature_columns) for one variant."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
    frac = 0.0 if mode == "clean" else malicious_fraction

    if dataset == "synthetic":
        from .scenario import ScenarioConfig, build_synthetic_scenario
        from ..data.synthetic import simulate
        from ..invariants.plants import synthetic_invariants
        sc = build_synthetic_scenario(ScenarioConfig(
            n_clients=n_clients, malicious_fraction=frac, fabrication=fabrication,
            steps_per_client=steps_per_client, window=window, seed=seed))
        calib = simulate(8000, seed=12345)
        inv_set = synthetic_invariants(calib, include_weak_bounds=False).calibrate(calib)
        sc["invariants"] = inv_set
        sc.update(client_verdicts(sc["clients"], inv_set))
    else:
        from .scenario_real import RealScenarioConfig, build_real_scenario
        from ..data.real import load_real
        normal, attack = load_real(dataset, data_dir)
        sc = build_real_scenario(normal, attack, RealScenarioConfig(
            n_clients=n_clients, malicious_fraction=frac, fabrication=fabrication,
            roll_shift=roll_shift, window=window, seed=seed, partition=partition,
            **({"target_attack_fraction": target_attack_fraction} if target_attack_fraction else {}),
            **(invariant_kw or {})))
        inv_set = sc["invariants"]

    cols = sc["columns"]
    if mode == "honest_only":
        sc["clients"] = [c for c in sc["clients"] if not c.is_malicious]
        sc["n_malicious"] = 0
        sc.update(summarise_verdicts([v for v in sc.get("physics_verdicts", [])
                                      if not v.get("is_malicious", True)]))
        return sc, inv_set, cols
    if mode not in ("projected", "gated"):
        return sc, inv_set, cols

    scaler = sc["scaler"]
    stats: list = []
    for c in sc["clients"]:
        if not c.is_malicious:
            continue
        _, disc = classify_channels(c.raw)
        protect = tuple(x for x in cols if x in disc) if protect_status else ()
        t0 = time.time()
        projected = project_batch(c.raw, inv_set, cols, protect=protect,
                                  target_violating=target_violating)
        v = inv_set.batch_verdict(projected)
        stat = projection_cost(c.raw, projected, cols)
        stat.update({"client": c.client_id, "violating_after": v["violating_fraction"],
                     "admitted_after": v["admitted"], "seconds": round(time.time() - t0, 2)})
        stats.append(stat)
        W, _ = make_windows(projected, window, cols)
        if c.train_index is not None:
            W = W[c.train_index]                 # same oversampling as the fabricated client
        c.train = scaler(W).astype(np.float32)
        c.raw = projected
        log.info("client %d projected: violating %.4f admitted %s shift %.3f sigma (%.0fs)",
                 c.client_id, v["violating_fraction"], v["admitted"],
                 stat["mean_abs_shift_sigma"], stat["seconds"])
    sc["projection"] = stats
    honest_v = [v for v in sc.get("physics_verdicts", []) if not v.get("is_malicious", True)]
    mal_v = [{"client": s["client"], "is_malicious": True,
              "violating_fraction": s["violating_after"], "admitted": s["admitted_after"]} for s in stats]
    sc.update(summarise_verdicts(honest_v + mal_v))
    if proj_stats is not None:
        proj_stats.extend(stats)
    if mode == "gated":
        # The deployed gate does not know who is honest: any client whose batch
        # fails the check sits out the round. (Honest rejections are counted so
        # the paper can report them; on the real records they are zero.)
        rej_mal = {v["client"] for v in mal_v if not v["admitted"]}
        rej_hon = {v["client"] for v in honest_v if not v["admitted"]}
        rejected = rej_mal | rej_hon
        sc["clients"] = [c for c in sc["clients"] if c.client_id not in rejected]
        sc["n_excluded_by_gate"] = len(rejected)
        sc["n_malicious_excluded_by_gate"] = len(rej_mal)
        sc["n_honest_excluded_by_gate"] = len(rej_hon)
        sc["n_malicious"] = sum(c.is_malicious for c in sc["clients"])
        log.info("gate excluded %d of %d malicious clients and %d honest; %d clients remain",
                 len(rej_mal), len(stats), len(rej_hon), len(sc["clients"]))
    return sc, inv_set, cols
