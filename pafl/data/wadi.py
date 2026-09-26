"""WADI loader.

WADI is the Water Distribution testbed at iTrust, SUTD: 123 process channels at
one row per second, a 14-day normal record and a 2-day attack record with 15
attacks. It is a distribution network, so it pairs with SWaT (treatment) as the
second physical testbed. Quirks of the October 2017 release, handled once here
(they are documented in ../zhu-2025-reprod/DATA_NOTES.md):

* a four-line metadata preamble before the header;
* column names are OPC paths ending in the tag, e.g.
  \\\\WIN-25J4RO10SBF\\LOG_DATA\\SUTD_WADI\\LOG_DATA\\1_FIT_001_PV -> 1_FIT_001_PV;
* Row, Date and Time columns instead of a timestamp;
* no inline label: the attack record's labels come from attack_description.xlsx,
  whose sheet has a header on the "S.No" row, a year typo, dots in times and
  continuation rows for later phases of the same attack;
* three aggregate, non-physical columns (plant start/stop log, leak differential
  pressure, total consumer required flow) are dropped, as in Zhu et al. 2025.
"""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

DROP_TAGS = ("PLANT_START_STOP_LOG", "LEAK_DIFF_PRESSURE", "TOTAL_CONS_REQUIRED_FLOW")
ATTACK_T0 = pd.Timestamp("2017-10-09 18:00:00")     # first row of WADI_attackdata.csv


def _header_row(path: Path, probe: int = 10) -> int:
    with open(path, "r", errors="replace") as f:
        for i in range(probe):
            line = f.readline()
            if line.lstrip().startswith("Row,") or line.count(",") > 10:
                return i
    return 0


def _tag(col: str) -> str:
    c = str(col).strip()
    return c.rsplit("\\", 1)[-1] if "\\" in c else c


def load_wadi(path: str | Path, nrows: int | None = None, downsample: int = 1,
              attack_sheet: str | Path | None = None) -> pd.DataFrame:
    """Read one WADI file and return a clean, typed frame with ATT_FLAG and datetime.

    attack_sheet : attack_description.xlsx; when given, ATT_FLAG is built from
        its start/end times (attack file only). Without it ATT_FLAG is all zero.
    """
    path = Path(path)
    hdr = _header_row(path)
    df = pd.read_csv(path, skiprows=hdr, header=0, nrows=nrows, low_memory=False)
    df.columns = [_tag(c) for c in df.columns]
    df = df.loc[:, [c for c in df.columns if not c.startswith("Unnamed")]]

    if "Date" in df.columns and "Time" in df.columns:
        df["datetime"] = pd.to_datetime(df["Date"].astype(str).str.strip() + " " +
                                        df["Time"].astype(str).str.strip(),
                                        format="%m/%d/%Y %I:%M:%S.%f %p", errors="coerce")
        df = df.drop(columns=["Date", "Time"])
    df = df.drop(columns=[c for c in ("Row",) + DROP_TAGS if c in df.columns])

    for c in df.columns:
        if c == "datetime":
            continue
        df[c] = pd.to_numeric(df[c], errors="coerce")

    # Four channels of this release are entirely empty (2_LS_001_AL, 2_LS_002_AL,
    # 2_P_001_STATUS, 2_P_002_STATUS); a handful of analyser channels have short
    # gaps. A NaN anywhere in a window makes the whole window unscorable, so drop
    # the empty channels and fill the gaps from neighbouring rows.
    feats = [c for c in df.columns if c != "datetime"]
    empty = [c for c in feats if df[c].isna().all()]
    df = df.drop(columns=empty)
    feats = [c for c in feats if c not in empty]
    df[feats] = df[feats].ffill().bfill()
    df.attrs["dropped_empty_channels"] = empty

    df["ATT_FLAG"] = 0
    if attack_sheet is not None:
        lab = attack_labels(attack_sheet, len(df))
        df["ATT_FLAG"] = lab.astype(int)

    if downsample > 1:
        df = df.iloc[::downsample]
    df = df.reset_index(drop=True)
    df.attrs["source"] = str(path)
    df.attrs["n_attack_rows"] = int(df["ATT_FLAG"].sum())
    return df


def attack_labels(sheet: str | Path, n_rows: int, t0: pd.Timestamp = ATTACK_T0) -> np.ndarray:
    """0/1 per row of the attack record, from the attack_description.xlsx times."""
    x = pd.read_excel(sheet, header=None)
    hdr = next(i for i in range(len(x)) if str(x.iloc[i, 0]).strip() == "S.No")
    df = x.iloc[hdr + 1:].copy()
    df.columns = [str(c).strip() for c in x.iloc[hdr].tolist()]

    def fix_time(t):
        if hasattr(t, "strftime"):
            return t.strftime("%H:%M:%S")
        return str(t).strip().replace(".", ":")

    lab = np.zeros(n_rows, bool)
    cur_date = None
    for _, r in df.iterrows():
        d, st, et = r.get("Date"), r.get("Start Time"), r.get("End Time")
        if pd.notna(d):
            try:
                d = pd.Timestamp(d)
                if d.year < 2000:
                    d = d.replace(year=2017)
                if not (pd.Timestamp("2017-10-09") <= d <= pd.Timestamp("2017-10-11 23:59")) \
                        and d.day in (9, 10, 11):
                    d = d.replace(year=2017, month=10)
                cur_date = d.date()
            except Exception:
                pass
        if pd.isna(st) or pd.isna(et) or cur_date is None:
            continue
        try:
            s = pd.Timestamp(f"{cur_date} {fix_time(st)}")
            e = pd.Timestamp(f"{cur_date} {fix_time(et)}")
            if e < s:
                e += pd.Timedelta(days=1)
            si, ei = int((s - t0).total_seconds()), int((e - t0).total_seconds())
            if 0 <= si < n_rows and ei > si:
                lab[si:min(ei, n_rows)] = True
        except Exception:
            continue
    return lab


def find_wadi_files(folder: str | Path) -> dict[str, Path]:
    folder = Path(folder)
    out: dict[str, Path] = {}
    for p in sorted(folder.rglob("*")):
        n = p.name.lower()
        if p.suffix.lower() == ".csv" and "14days" in n:
            out.setdefault("normal", p)
        elif p.suffix.lower() == ".csv" and "attack" in n:
            out.setdefault("attack", p)
        elif p.suffix.lower() == ".xlsx" and "attack_description" in n:
            out.setdefault("sheet", p)
    if "normal" not in out or "attack" not in out:
        raise FileNotFoundError(f"WADI needs WADI_14days.csv and WADI_attackdata.csv under {folder}; found {list(out)}")
    return out
