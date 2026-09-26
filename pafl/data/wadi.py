"""WADI loader.

WADI is the Water Distribution testbed at iTrust, SUTD: 127 tag columns at one
row per second, a 14-day normal record (1,209,601 rows) and a 2-day attack
record (172,801 rows) with 15 attacks. It is a distribution network, so it pairs
with SWaT (treatment) as the second physical testbed. The loader keeps 120
channels. Quirks of the October 2017 release, all handled here:

* a four-line metadata preamble before the header;
* column names are OPC paths ending in the tag, e.g.
  \\\\WIN-25J4RO10SBF\\LOG_DATA\\SUTD_WADI\\LOG_DATA\\1_FIT_001_PV -> 1_FIT_001_PV;
* Row, Date and Time columns instead of a timestamp;
* no inline label: the attack record's labels come from attack_description.xlsx,
  whose sheet has a header on the "S.No" row, a year typo, dots in times and
  continuation rows for later phases of the same attack;
* three aggregate, non-physical columns (plant start/stop log, leak differential
  pressure, total consumer required flow) are dropped, as in Zhu et al. 2025.

No rows are dropped from either record; Zhu et al.'s split drops the first
20,000 normal rows, this one does not. The 5 s stride is applied afterwards, in
pafl.data.real.
"""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

DROP_TAGS = ("PLANT_START_STOP_LOG", "LEAK_DIFF_PRESSURE", "TOTAL_CONS_REQUIRED_FLOW")
ATTACK_T0 = pd.Timestamp("2017-10-09 18:00:00")     # first row of WADI_attackdata.csv


def _header_row(path: Path, probe: int = 10) -> int:
    """Zero-based line of the column header, after the metadata preamble."""
    with open(path, "r", errors="replace") as f:
        for i in range(probe):
            line = f.readline()
            if line.lstrip().startswith("Row,") or line.count(",") > 10:
                return i
    return 0


def _tag(col: str) -> str:
    """The tag at the end of an OPC path; other names pass through."""
    c = str(col).strip()
    return c.rsplit("\\", 1)[-1] if "\\" in c else c


def load_wadi(path: str | Path, nrows: int | None = None, downsample: int = 1,
              attack_sheet: str | Path | None = None) -> pd.DataFrame:
    """Read one WADI file and return a clean, typed frame with ATT_FLAG and datetime.

    attack_sheet : attack_description.xlsx; when given, ATT_FLAG is built from
        its start/end times (attack file only). Without it ATT_FLAG is all zero.
        The labels are computed on the full-resolution rows, before
        `downsample`, because `attack_labels` maps a time to a row index.
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
    # the empty channels and fill the gaps from neighbouring rows. Both steps
    # run per file, so the two records keep the same 120 channels only because
    # the same four are empty in each.
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
    """0/1 per row of the attack record, from the attack_description.xlsx times.

    A time maps to row (time - t0) in seconds. That is valid because the WADI
    attack record is gap-free at 1 Hz, which the SWaT attack historian is not
    (SWaT uses its inline labels instead). An interval covers [start, end).

    Sheet quirks repaired here: the header sits on the "S.No" row; one date
    reads 1947 and is taken as 2017; five dates read July (2017-07-11) and are
    taken as October; times may use a dot for a colon ("11.30:40"); a row
    without a date takes the date of the row above; an end time before its
    start is taken to cross midnight. The 15 attacks (16 intervals, counting
    the second phase of attack 7) give 14 contiguous labelled segments,
    because two pairs overlap: 9,971 rows at 1 Hz, 1,996 at the 5 s stride.
    """
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
    """Locate WADI_14days.csv, WADI_attackdata.csv and attack_description.xlsx.

    The search is recursive and matches on name fragments ("14days", "attack",
    "attack_description"), taking the first match in sorted path order. The
    sheet is optional here, but pafl.data.real refuses an attack record whose
    labels come out empty, so in practice all three files are required.
    """
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
