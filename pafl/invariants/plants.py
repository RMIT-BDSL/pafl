"""Hand-written invariant sets.

Feng et al. mine invariants automatically, and pafl.invariants.mine does that.
`synthetic_invariants` is the ground truth for the simulated plant: the set the
simulated federations use (pafl.fl.variants), and the reference the miner is
checked against (tests/test_invariants.py). If the miner cannot recover the
mass balance of a plant whose physics we wrote ourselves, it will not recover
anything on a real record either.

`batadal_invariants` below is a pilot-era draft that nothing calls: the
registry `PLANTS` is unused too. It is not the BATADAL set of any result; see
`pafl.data.batadal.batadal_invariants` (same name, different function) and
`pafl.data.swat.swat_invariants`.
"""
from __future__ import annotations
import pandas as pd
from .spec import InvariantSet, mass_balance, status_flow_coupling, range_bound


def synthetic_invariants(df: pd.DataFrame, include_weak_bounds: bool = True) -> InvariantSet:
    """Ground-truth invariants for pafl.data.synthetic.simulate output.

    Areas, pump ratings and dt come from the frame's `attrs["plant"]`, so the
    set is exact for the site that produced `df`; a site with another
    `site_shift` obeys it only approximately, which the calibration's safety
    factor absorbs. The couplings use the default 0 = off, 1 = on encoding.
    The bounds [0, 12] m bracket the simulator's clip on tank level (0.05 to
    12 m).
    """
    meta = df.attrs.get("plant")
    if meta is None:
        raise ValueError("dataframe carries no plant metadata; pass the simulate() output")
    area, qnom, dt = meta["area"], meta["qnom"], meta["dt"]
    invs = []
    for i in range(meta["n_tanks"]):
        invs.append(mass_balance(f"L_T{i+1}", f"F_PU{i+1}", f"F_PU{i+2}", area[i], dt))
    for i in range(meta["n_pumps"] - 1):        # the outlet pump is demand-scaled, so skip it
        invs.append(status_flow_coupling(f"S_PU{i+1}", f"F_PU{i+1}", qnom[i]))
    if include_weak_bounds:
        for i in range(meta["n_tanks"]):
            invs.append(range_bound(f"L_T{i+1}", 0.0, 12.0))
    return InvariantSet(invs, name="synthetic")


def batadal_invariants(area: dict[str, float] | None = None, dt: float = 1.0) -> InvariantSet:
    """C-Town water distribution, as published in the BATADAL corpus. Unused.

    Kept for the record of what was tried. scripts/separation.py once called it,
    and every fabrication was admitted at a violating fraction of 0.0000,
    because these assumed tank areas do not match the network. The couplings
    are also degenerate: with nominal=0.0 the residual is the flow itself,
    whatever the status, so they cannot tell a running pump from a stopped one.

    BATADAL samples hourly, levels are in metres and flows in litres per second,
    so the balance carries a unit factor of 3600/1000 = 3.6 to reach cubic metres
    per hour. Tank areas are not distributed with the dataset; the defaults below
    were taken as the values commonly used in the BATADAL literature and were
    never checked against the C-Town network file.
    """
    area = area or {"T1": 100.0, "T2": 150.0, "T3": 100.0,
                    "T4": 100.0, "T5": 60.0, "T6": 100.0, "T7": 100.0}
    unit = 3.6 * dt
    topology = {                      # tank: (inflows, outflows)
        "T1": (["F_PU1", "F_PU2"], ["F_PU4", "F_PU5", "F_PU6", "F_PU7"]),
        "T2": (["F_V2"], []),
        "T3": (["F_PU4", "F_PU5"], ["F_PU8"]),
        "T4": (["F_PU7"], []),
        "T5": (["F_PU8"], ["F_PU10", "F_PU11"]),
        "T6": (["F_PU10"], []),
        "T7": (["F_PU11"], []),
    }
    invs = []
    for tank, (ins, outs) in topology.items():
        terms = [(c, unit / area[tank]) for c in ins] + [(c, -unit / area[tank]) for c in outs]
        if not terms:
            continue
        from .spec import linear_relation
        invs.append(linear_relation(f"L_{tank}", terms, diff_target=True, name=f"balance::L_{tank}"))
    for i in list(range(1, 12)):
        invs.append(status_flow_coupling(f"S_PU{i}", f"F_PU{i}", nominal=0.0,
                                         name=f"coupling::S_PU{i}~F_PU{i}"))
    return InvariantSet(invs, name="batadal")


PLANTS = {"synthetic": synthetic_invariants, "batadal": batadal_invariants}
