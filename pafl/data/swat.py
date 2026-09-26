"""SWaT loader and invariant set.

SWaT is the Secure Water Treatment testbed at iTrust, SUTD. It is a full,
six-stage water treatment plant with 51 sensors and actuators, recorded at one
row per second. Two properties make it the strongest real dataset for this
paper, stronger than BATADAL and unlike HAI:

* It switches actuators constantly. Every stage has motorised valves (MV*) and
  pumps (P*) that open and close as tanks fill and drain. The actuator-to-flow
  coupling family -- a pump that reads off moves no water -- therefore has many
  exact relations to attach to. This is the invariant family a channel-roll
  fabrication destroys, so SWaT is where the attack and the defence meet on real
  data with the most surface.
* It stores mass. Each stage has a tank with a level sensor (LIT*) driven by
  measured inflow and outflow (FIT*). The mass-balance family fits well.

The loader handles the quirks of the distributed files once, so no downstream
code has to know about them:

* The published files ship as .xlsx with a title in row 1 and the real header in
  row 2. A .csv export is also accepted. `openpyxl` is required for .xlsx.
* Column names carry stray leading and trailing spaces. They are stripped.
* The label column is named "Normal/Attack" (sometimes with a trailing space)
  and holds the strings "Normal" and "Attack". It is mapped to an integer
  ATT_FLAG (1 = attack) to match the BATADAL convention, so every downstream
  script treats the two datasets the same way.
* The Timestamp column is parsed to a datetime, kept for reference under the
  lower-case name `datetime`, and never fed to a model.

The A1 & A2 (Dec 2015) collection is the canonical split: one file of about
seven days of normal operation, and one file of about four days containing 36
labelled attacks. Use the normal file to build and calibrate invariants, and the
attack file to measure detection.
"""
from __future__ import annotations
from pathlib import Path
import re
import numpy as np
import pandas as pd

from ..invariants.spec import InvariantSet, status_flow_coupling, linear_relation
from ..invariants.mine import (
    classify_channels, mine_linear_balances, mine_couplings,
)

# columns that are never features, matched case-insensitively by prefix/name
_LABEL_NAMES = ("normal/attack", "attack", "label", "att_flag")
_TIME_NAMES = ("timestamp", "datetime", "time")


def _find_header_row(path: Path, probe: int = 5) -> int:
    """Return the zero-based row that holds the real column header.

    The SWaT .xlsx files put a human title in the first row. The header is the
    first row that contains the label column name. If none is found in the first
    `probe` rows the file is assumed to have a normal header at row 0.
    """
    head = pd.read_excel(path, header=None, nrows=probe, engine="openpyxl")
    for r in range(len(head)):
        cells = [str(x).strip().lower() for x in head.iloc[r].tolist()]
        if any(any(ln == c or c.startswith("normal/attack") for ln in _LABEL_NAMES)
               for c in cells):
            return r
    return 0


def load_swat(path: str | Path, nrows: int | None = None,
              downsample: int = 1) -> pd.DataFrame:
    """Read one SWaT file (.xlsx or .csv) and return a clean, typed dataframe.

    Parameters
    ----------
    path : the Normal or Attack file.
    nrows : read at most this many data rows. Use it on Colab to work on a
        sample; leave it None for the full record on AWS.
    downsample : keep every `downsample`-th row. SWaT is one row per second and
        the plant does not change state every second, so a stride of 5 or 10
        cuts the size with almost no loss of dynamics. Applied after nrows.

    The returned frame has an ATT_FLAG column (1 = attack, 0 = normal), a
    `datetime` column for reference, and float feature columns for everything
    else.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in (".xlsx", ".xls"):
        hdr = _find_header_row(path)
        df = pd.read_excel(path, header=hdr, nrows=nrows, engine="openpyxl")
    elif suffix in (".csv", ".txt"):
        # a stray title line is possible in CSV exports too; sniff for it
        first = pd.read_csv(path, header=None, nrows=1).iloc[0].tolist()
        looks_titled = not any(str(x).strip().lower().startswith("normal/attack")
                               or str(x).strip().lower() in ("timestamp", "datetime")
                               for x in first)
        df = pd.read_csv(path, header=1 if looks_titled else 0, nrows=nrows)
    else:
        raise ValueError(f"unsupported SWaT file type: {path.name!r}")

    df.columns = [str(c).strip() for c in df.columns]

    # --- label column -> ATT_FLAG (1 = attack) ---
    label_col = None
    for c in df.columns:
        if c.strip().lower() in _LABEL_NAMES or c.strip().lower().startswith("normal/attack"):
            label_col = c
            break
    if label_col is not None:
        s = df[label_col].astype(str).str.strip().str.lower()
        # "attack" (and the occasional "a ttack") -> 1, everything else -> 0
        df["ATT_FLAG"] = s.str.startswith("a").astype(int)
        if label_col != "ATT_FLAG":
            df = df.drop(columns=[label_col])
    else:
        df["ATT_FLAG"] = 0

    # --- timestamp -> datetime, dropped from features ---
    for c in list(df.columns):
        if c.strip().lower() in _TIME_NAMES and c != "ATT_FLAG":
            df["datetime"] = pd.to_datetime(df[c], errors="coerce")
            if c != "datetime":
                df = df.drop(columns=[c])
            break

    # --- everything else is a numeric feature ---
    for c in df.columns:
        if c in ("datetime", "ATT_FLAG"):
            continue
        df[c] = pd.to_numeric(df[c], errors="coerce")

    if downsample > 1:
        df = df.iloc[::downsample]

    df = df.reset_index(drop=True)
    df.attrs["source"] = str(path)
    df.attrs["n_attack_rows"] = int(df["ATT_FLAG"].sum())
    return df


def find_swat_files(folder: str | Path) -> dict[str, Path]:
    """Locate the normal and attack files inside a SWaT release folder.

    Returns a dict with keys 'normal' and 'attack' where found. Matching is by
    name and ignores case, so both "SWaT_Dataset_Normal_v1.xlsx" and a renamed
    CSV export are found. Raises FileNotFoundError if the folder holds no
    readable SWaT file at all.
    """
    folder = Path(folder)
    cands = [p for p in folder.rglob("*")
             if p.suffix.lower() in (".xlsx", ".xls", ".csv")
             and not p.name.startswith(("~$", "."))
             and "list" not in p.name.lower()]     # List_of_attacks_Final.xlsx is metadata

    # Prefer the process-data files ("SWaT_Dataset_...") over anything else in
    # the release folder, and a CSV export over the .xlsx it came from: the
    # spreadsheet takes over a minute to parse, the CSV a few seconds.
    def rank(p: Path):
        m = re.search(r"_v(\d+)", p.stem.lower())
        version = int(m.group(1)) if m else -1
        return (0 if "dataset" in p.name.lower() else 1,
                0 if p.suffix.lower() == ".csv" else 1,
                -version,                                  # v1 is the corrected release
                p.name.lower())

    out: dict[str, Path] = {}
    for p in sorted(cands, key=rank):
        n = p.name.lower()
        if "normal" in n and "normal" not in out:
            out["normal"] = p
        elif "attack" in n and "attack" not in out:
            out["attack"] = p
    if not out:
        raise FileNotFoundError(
            f"no SWaT .xlsx/.csv file found under {folder}. Expected names "
            f"containing 'Normal' and 'Attack'.")
    return out


def swat_invariants(clean: pd.DataFrame, max_invariants: int = 40,
                    r2_min: float = 0.60, coupling_support: float = 0.02,
                    coupling_off_ratio: float = 0.05) -> tuple[InvariantSet, dict]:
    """Build the SWaT invariant set from a clean (normal-operation) frame.

    SWaT has far more channels than BATADAL, so this uses the automatic miners
    rather than the hand-named S_/F_ pairing that BATADAL uses. Two families are
    kept, and the report states exactly what was found, because those counts go
    in the paper:

    * Actuator-to-flow couplings, from `mine_couplings`: an actuator state that
      predicts whether a flow sensor reads zero or a stable nominal value. On
      SWaT these hold nearly exactly and are the family a channel roll breaks.
    * Mass balances, from `mine_linear_balances`, kept only where the linear fit
      on the driving flows reaches r2_min. A loose balance is dropped rather
      than kept, because it only raises the honest false-rejection rate.

    The set is NOT calibrated here. Call `.calibrate(clean_holdout)` on a second
    clean slice so the tolerances are set on data the invariants were not fitted
    to, which is what keeps the false-rejection number honest.
    """
    cont, disc = classify_channels(clean)
    report: dict = {"n_continuous": len(cont), "n_discrete": len(disc),
                    "couplings": [], "balances": [], "dropped_balances": []}

    invs = []

    # --- couplings: discrete actuator -> flow sensor ---
    for c in mine_couplings(clean, min_support=coupling_support,
                            max_off_ratio=coupling_off_ratio):
        invs.append(status_flow_coupling(c.status, c.flow, c.nominal,
                                         name=f"coupling::{c.status}~{c.flow}",
                                         off_value=c.off_value, on_value=c.on_value,
                                         steady_only=True))
        cv = float(c.on_std / (abs(c.nominal) + 1e-12))
        report["couplings"].append({"status": c.status, "flow": c.flow,
                                    "nominal": round(float(c.nominal), 3),
                                    "cv": round(cv, 4),
                                    "off_q99": round(float(c.off_max), 4),
                                    "off_value": c.off_value, "on_value": c.on_value,
                                    "support": round(float(c.support), 4)})

    # --- mass balances, gated on fit quality ---
    for r in mine_linear_balances(clean, alpha=5e-4, max_terms=8):
        entry = {"tank": r.target, "r2": round(float(r.r2), 4),
                 "tightness": round(float(r.tightness), 4)}
        if r.r2 >= r2_min:
            invs.append(linear_relation(r.target, r.terms, r.const, diff_target=True,
                                        name=f"balance::{r.target}"))
            report["balances"].append(entry)
        else:
            report["dropped_balances"].append(entry)

    # keep the strongest, if the miner over-produced
    invs = invs[:max_invariants]

    inv_set = InvariantSet(invs, name="swat")
    report["kept_total"] = len(invs)
    report["kept_couplings"] = len(report["couplings"])
    report["kept_balances"] = len(report["balances"])
    return inv_set, report
