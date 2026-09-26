"""BATADAL loader and the hand-paired BATADAL invariant set.

BATADAL is the C-Town water distribution network, simulated in EPANET. Two
properties made it the pilot's first dataset. Its files are a few megabytes, so
it needs no special transfer. And its network model is published, so the physics
is knowable rather than guessed. In the paper it is the support record: its
committed federated runs use 5 clients rather than 10 and no downsampling (one
row per hour), and they build their invariants with
`pafl.data.swat.swat_invariants`, not with `batadal_invariants` below.

Three quirks in the distributed files must be handled, and each is handled here
once so no downstream code has to know about them:

* The second training file has a leading space in every column name.
* The second training file marks unlabelled rows with ATT_FLAG = -999. Those are
  rows the organisers did not label, not attack rows. This loader treats them as
  normal, which is the conservative choice: it can only understate detection, not
  inflate it.
* The DATETIME column is a string (dd/mm/yy hh). It is renamed `datetime` and
  kept as that string, not parsed; being non-numeric, it never enters the
  feature set or a model.

A finding worth stating up front, because it shapes which invariants are used.
On this distribution network the mass balances are only partial: a tank's
level is driven by pressure at junctions, and the pump-flow sensors do not
measure the pipe flow into the tank. The relations that hold exactly are the
actuator-to-flow couplings -- a pump that reads off moves no water -- and those
are precisely what a channel-roll fabrication (the paper's naive attack)
destroys. So the exact invariants and the fabrication that beats every
per-channel statistic meet on a published network.
"""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

from ..invariants.spec import InvariantSet, status_flow_coupling, linear_relation
from ..invariants.mine import mine_linear_balances


def load_batadal(path: str | Path, kind: str = "auto") -> pd.DataFrame:
    """Read one BATADAL CSV and return a clean, typed dataframe.

    dataset03 is a year of normal operation (8,761 rows); dataset04 is about
    six months, partly labelled, with 219 attack rows in 5 contiguous
    segments. `kind` ('clean', 'attack', 'auto') is accepted but has no
    effect: both files go through the same parsing.
    """
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    if "DATETIME" in df.columns:
        # keep it for reference, drop it from anything numeric
        df = df.rename(columns={"DATETIME": "datetime"})

    if "ATT_FLAG" in df.columns:
        flag = pd.to_numeric(df["ATT_FLAG"], errors="coerce").fillna(0).astype(int)
        # -999 means "not labelled", which this loader treats as normal
        df["ATT_FLAG"] = (flag == 1).astype(int)

    for c in df.columns:
        if c in ("datetime", "ATT_FLAG"):
            continue
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df = df.reset_index(drop=True)
    df.attrs["source"] = str(path)
    df.attrs["n_attack_rows"] = int(df.get("ATT_FLAG", pd.Series(dtype=int)).sum())
    return df


def batadal_invariants(clean: pd.DataFrame, r2_min: float = 0.60,
                       coupling_cv_max: float = 0.10) -> tuple[InvariantSet, dict]:
    """Build the hand-paired invariant set for BATADAL from a clean dataframe.

    scripts/separation.py uses it for the "expert" criterion-1 set
    (results/c1_batadal_expert.json), and tests/test_batadal.py covers it. The
    federated BATADAL runs do not; they use `pafl.data.swat.swat_invariants`.

    Two families are kept, and the report says exactly what was found and what
    was dropped, because those counts are numbers the paper reports.

    * Actuator-to-flow couplings, kept when the pump moves no water while off and
      its on-flow is stable (coefficient of variation below the threshold). On
      this network these hold essentially exactly. Each S_x is paired with the
      F_x of the same name, with the 0 = off, 1 = on encoding and without the
      steady-state filter that `swat_invariants` applies.
    * Mass balances, kept only for tanks where a linear fit on the pump flows
      reaches r2_min. On a distribution network several tanks fail this, and
      keeping a loose balance would only raise the false-rejection rate.
    """
    invs = []
    report = {"couplings": [], "balances": [], "dropped_balances": []}

    # --- couplings ---
    status_cols = [c for c in clean.columns if c.upper().startswith("S_")]
    for s in status_cols:
        f = "F_" + s[2:]
        if f not in clean.columns:
            continue
        S = clean[s].to_numpy(float)
        F = clean[f].to_numpy(float)
        on = F[S >= S.max()] if S.max() > 0 else np.array([])
        off = F[S <= S.min()]
        # "Off" must mean no flow at all (below 1e-3 in the record's flow units).
        # A pump that is always on has on == off rows and fails this; one that
        # is always off has no on rows and fails the size test below.
        off_ok = (np.abs(off).max() < 1e-3) if off.size else True
        if on.size < 20:            # a pump that essentially never runs: skip, no information
            continue
        nominal = float(on.mean())
        cv = float(on.std() / (abs(nominal) + 1e-9))
        if off_ok and cv <= coupling_cv_max:
            invs.append(status_flow_coupling(s, f, nominal, name=f"coupling::{s}~{f}"))
            report["couplings"].append({"status": s, "flow": f, "nominal": round(nominal, 3),
                                        "cv": round(cv, 4)})

    # --- mass balances, kept only where the fit is good enough ---
    for r in mine_linear_balances(clean, alpha=5e-4, max_terms=8):
        entry = {"tank": r.target, "r2": round(r.r2, 4), "tightness": round(r.tightness, 4)}
        if r.r2 >= r2_min:
            invs.append(linear_relation(r.target, r.terms, r.const, diff_target=True,
                                        name=f"balance::{r.target}"))
            report["balances"].append(entry)
        else:
            report["dropped_balances"].append(entry)

    inv_set = InvariantSet(invs, name="batadal")
    report["kept_total"] = len(invs)
    report["kept_couplings"] = len(report["couplings"])
    report["kept_balances"] = len(report["balances"])
    return inv_set, report
