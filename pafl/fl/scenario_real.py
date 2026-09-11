"""Assemble a federation from a real testbed record (SWaT, WADI, BATADAL).

This is the real-data twin of `scenario.build_synthetic_scenario`. It returns
the same dict shape, so `run_federation` and every downstream script treat a
real federation and a simulated one identically.

The construction follows the threat model in the paper, and it mirrors the
simulated construction step for step so that the two settings measure the same
attack:

* One normal record is split into clients by `partition.partition_frame`.
  Honest clients window their own shard and train on it.
* A malicious client wants the shared detector to stop flagging a particular
  attack. Whole labelled attack segments from the attack file, standing in for
  an attack the adversary has seen, are spliced into its shard in place of an
  equal number of honest rows. The shard is then fabricated as a whole (Recipe
  A or B), the labels are dropped, and the client oversamples the windows that
  carry the attack to `poison_strength` of its training set. For a
  reconstruction detector this is the natural targeted objective: teach the
  shared model to reconstruct that attack well, so it stops looking anomalous
  to anyone in the federation.
* The batch the physics check sees (`ClientData.raw`) is the whole fabricated
  shard, spliced attack rows included. An earlier version mixed pre-windowed
  attack windows into the training set after fabrication, so the check never
  saw them and the projected attacker could not be built consistently. Now the
  check, the fabrication and the projection all act on one object, and
  `ClientData.train_index` records the oversampling so the projected variant
  reproduces it exactly.
* The attack file is never partitioned. It is the shared, held-out test set,
  identical for every client, and the alarm threshold is calibrated on a clean
  slice, never on it.

Invariants are mined and calibrated on clean data the malicious clients never
touch, so the admission check is fair: it was not fitted to the attack.
"""
from __future__ import annotations
from dataclasses import dataclass
import numpy as np
import pandas as pd

from ..data.loaders import ClientData, Scaler, feature_columns, make_windows
from ..data.swat import swat_invariants
from ..attacks.recipe_a import fabricate as fabricate_a, FABRICATIONS
from ..invariants.spec import InvariantSet
from ..utils.logging import get_logger
from .partition import PartitionConfig, partition_frame

log = get_logger("pafl.scenario_real")


@dataclass
class RealScenarioConfig:
    n_clients: int = 10
    malicious_fraction: float = 0.3
    fabrication: str = "channel_roll"     # a Recipe A name, or "recipe_b"
    roll_shift: int | None = None         # channel_roll shift in rows; None = the recipe's 7.
                                          # State it in plant time: SWaT at a 5 s stride needs
                                          # 60 rows for a 5 min misalignment.
    partition: str = "temporal"           # temporal | iid
    window: int = 10
    seed: int = 0
    poison_strength: float = 0.5          # share of a malicious client's windows drawn from attack windows
    update_attack: str | None = None      # if set, malicious clients keep honest data and attack the update
    update_attack_kw: dict | None = None
    target_attack_fraction: float = 0.25  # share of a malicious shard's rows replaced by attack segments
    val_fraction: float = 0.15            # clean slice for threshold calibration
    root_fraction: float = 0.05           # clean slice the server holds for FLTrust
    invariant_fraction: float = 0.30      # clean slice invariants are fitted on
    max_invariants: int = 40
    # Miner thresholds (see pafl.data.swat.swat_invariants). These decide how
    # many attacks the invariant set can see, which on real data decides how
    # much poison the gate can remove. On SWaT the defaults give 5 invariants
    # covering 12 of 35 attack segments (10 % of attack rows); r2_min 0.40 with
    # coupling_off_ratio 0.10 and coupling_support 0.005 gives 9 invariants
    # covering 20 segments (82 % of attack rows) at 0.36 % honest violations.
    r2_min: float = 0.60
    coupling_off_ratio: float = 0.05
    coupling_support: float = 0.02
    # Channels excluded from the detector's features (not from the invariants).
    # SWaT's AIT analyser channels drift by several standard deviations between
    # the normal and the attack record: on the attack file's own normal rows,
    # 60-80 % exceed |z| > 3 on AIT201/202/402/501/502/504. A detector trained
    # on the normal file then flags two thirds of normal test windows for
    # reasons that have nothing to do with attacks, and no poisoning effect can
    # be read off. Excluding them is standard in the SWaT literature and the
    # paper states it. BATADAL has no such channels, so the default is harmless.
    exclude_channel_prefixes: tuple[str, ...] = ("AIT",)


def _fabricate(batch: pd.DataFrame, kind: str, cols: list[str], seed: int,
               inv_set: InvariantSet, window: int, roll_shift: int | None = None) -> pd.DataFrame:
    """Dispatch to Recipe A (a fixed transform) or Recipe B (optimised)."""
    if kind in FABRICATIONS:
        kw = {"shift": roll_shift} if (kind == "channel_roll" and roll_shift) else {}
        return fabricate_a(batch, kind, seed=seed, **kw)
    if kind == "recipe_b":
        from ..attacks.recipe_b import fabricate_recipe_b
        return fabricate_recipe_b(batch, inv_set, cols, window=window, seed=seed)
    raise KeyError(f"unknown fabrication {kind!r}")


def attack_segments(attack: pd.DataFrame, label_col: str = "ATT_FLAG") -> list[np.ndarray]:
    """Contiguous runs of labelled attack rows, as index arrays into `attack`."""
    y = attack[label_col].to_numpy(int) if label_col in attack.columns else np.zeros(len(attack), int)
    idx = np.where(y == 1)[0]
    if idx.size == 0:
        return []
    cuts = np.where(np.diff(idx) > 1)[0] + 1
    return [seg for seg in np.split(idx, cuts) if seg.size]


def choose_target_segments(attack: pd.DataFrame, budget_rows: int,
                           rs: np.random.Generator) -> list[np.ndarray]:
    """The attack segments one coordinated adversary tries to hide.

    Segments are drawn in random order until `budget_rows` is met; the last one
    is truncated to fit. Every malicious client splices this same set, which is
    what a single adversary controlling several clients would do, and it is what
    makes "recall on the targeted attacks" a well-defined number.
    """
    segs = attack_segments(attack)
    chosen: list[np.ndarray] = []
    if budget_rows <= 0 or not segs:
        return chosen
    placed = 0
    for k in rs.permutation(len(segs)):
        take = min(segs[k].size, budget_rows - placed)
        if take <= 0:
            break
        chosen.append(segs[k][:take])
        placed += take
        if placed >= budget_rows:
            break
    return chosen


def splice_attacks(shard: pd.DataFrame, attack: pd.DataFrame, cols: list[str],
                   fraction: float, rs: np.random.Generator,
                   segments: list[np.ndarray] | None = None) -> pd.DataFrame:
    """Write whole attack segments over about `fraction` of the shard's rows.

    `segments` are index arrays into `attack` (see `choose_target_segments`);
    if None they are drawn here. Each is written over a random stretch of the
    shard, so the shard keeps its length and every client stays the same size.
    The returned frame carries ATT_FLAG = 1 on the spliced rows so the caller
    can oversample them; the caller drops that label before training, because
    the client presents these rows as normal.
    """
    out = shard.copy().reset_index(drop=True)
    out[cols] = out[cols].astype(float)      # attack rows may carry interpolated values
    out["ATT_FLAG"] = 0
    n = len(out)
    if segments is None:
        segments = choose_target_segments(attack, int(round(n * fraction)), rs)
    for seg in segments:
        take = min(seg.size, n)
        if take <= 0:
            continue
        seg = seg[:take]
        start = int(rs.integers(0, n - take + 1))
        out.loc[start:start + take - 1, cols] = attack.iloc[seg][cols].to_numpy()
        out.loc[start:start + take - 1, "ATT_FLAG"] = 1
    return out


def targeted_window_mask(n_rows: int, segments: list[np.ndarray], window: int) -> np.ndarray:
    """Boolean over the windows of a frame: does the window touch a target row?"""
    rows = np.zeros(n_rows, bool)
    for seg in segments:
        rows[seg] = True
    n_win = n_rows - window + 1
    if n_win <= 0:
        return np.zeros(0, bool)
    c = np.concatenate([[0], np.cumsum(rows)])
    return (c[window:window + n_win] - c[:n_win]) > 0


def build_real_scenario(normal: pd.DataFrame, attack: pd.DataFrame,
                        cfg: RealScenarioConfig) -> dict:
    """Build a federation from a real normal record and a real attack record.

    normal : attack-free frame (e.g. SWaT normal file).
    attack : labelled frame with ATT_FLAG (e.g. SWaT attack file). Used for the
             shared test set and as the source of the attack segments a
             malicious client splices into its shard.
    """
    rs = np.random.default_rng(cfg.seed)
    cols = [c for c in feature_columns(normal)
            if not any(p.upper() in str(c).upper() for p in cfg.exclude_channel_prefixes)]

    # --- carve clean slices before any client sees the data ---
    n = len(normal)
    n_inv = int(n * cfg.invariant_fraction)
    n_val = int(n * cfg.val_fraction)
    n_root = int(n * cfg.root_fraction)
    # take the calibration slices from the front, leave the rest for clients
    inv_df = normal.iloc[:n_inv].reset_index(drop=True)
    val_df = normal.iloc[n_inv:n_inv + n_val].reset_index(drop=True)
    root_df = normal.iloc[n_inv + n_val:n_inv + n_val + n_root].reset_index(drop=True)
    client_pool = normal.iloc[n_inv + n_val + n_root:].reset_index(drop=True)

    # invariants: fit on one clean slice, calibrate tolerances on another
    fit_half = inv_df.iloc[: len(inv_df) // 2]
    cal_half = inv_df.iloc[len(inv_df) // 2:]
    inv_set, inv_report = swat_invariants(fit_half, max_invariants=cfg.max_invariants,
                                          r2_min=cfg.r2_min,
                                          coupling_off_ratio=cfg.coupling_off_ratio,
                                          coupling_support=cfg.coupling_support)
    inv_set.calibrate(cal_half)
    log.info("mined %d invariants (%d couplings, %d balances)",
             len(inv_set), inv_report["kept_couplings"], inv_report["kept_balances"])

    # --- scaler fitted on the pooled clean client data ---
    scaler = Scaler.fit(client_pool[cols].to_numpy(np.float32))

    # --- partition the client pool ---
    frames = partition_frame(client_pool, PartitionConfig(
        n_clients=cfg.n_clients, scheme=cfg.partition, seed=cfg.seed))

    n_mal = int(round(cfg.n_clients * cfg.malicious_fraction))
    mal_ids = set(rs.choice(cfg.n_clients, size=n_mal, replace=False).tolist()) if n_mal else set()

    # One coordinated adversary, one target set, drawn from its own generator so
    # that the clean, fabricated and projected federations of a seed share it.
    shard_rows = len(frames[0])
    targets = choose_target_segments(attack, int(round(shard_rows * cfg.target_attack_fraction)),
                                     np.random.default_rng(cfg.seed + 777))
    target_rows = int(sum(len(s) for s in targets))

    clients: list[ClientData] = []
    for i, df in enumerate(frames):
        malicious = i in mal_ids
        if malicious and cfg.update_attack:
            # update-space attacker: honest data, crafted update
            W, _ = make_windows(df, cfg.window, cols)
            clients.append(ClientData(i, scaler(W).astype(np.float32),
                                      np.zeros(len(W), np.int64), df, is_malicious=True,
                                      update_attack=cfg.update_attack,
                                      update_attack_kw=cfg.update_attack_kw))
            continue
        if malicious:
            # Attack segments from the real attack record, spliced into this
            # client's own shard; then the whole shard is fabricated so the
            # physics no longer holds, and presented to the trainer as normal.
            atk = splice_attacks(df, attack, cols, cfg.target_attack_fraction, rs,
                                 segments=targets)
            batch = _fabricate(atk, cfg.fabrication, cols, seed=cfg.seed + i,
                               inv_set=inv_set, window=cfg.window, roll_shift=cfg.roll_shift)
            batch["ATT_FLAG"] = 0
            _, y_true = make_windows(atk, cfg.window, cols)      # labels of the underlying attack
            W_fab, _ = make_windows(batch, cfg.window, cols)
            # Exposure, not label flipping: oversample the windows that carry
            # the attack so the shared detector learns to reconstruct it.
            atk_idx = np.where(y_true == 1)[0]
            ok_idx = np.where(y_true == 0)[0]
            sel = None
            if atk_idx.size and cfg.poison_strength > 0:
                n_take = int(len(W_fab) * cfg.poison_strength)
                draw_a = rs.choice(atk_idx, size=n_take, replace=True)
                draw_n = rs.choice(ok_idx, size=len(W_fab) - n_take, replace=True) \
                    if ok_idx.size else draw_a
                sel = np.concatenate([draw_a, draw_n])
                rs.shuffle(sel)
                W = W_fab[sel]
            else:
                W = W_fab
            clients.append(ClientData(i, scaler(W).astype(np.float32),
                                      np.zeros(len(W), np.int64), batch,
                                      is_malicious=True, fabrication=cfg.fabrication,
                                      train_index=sel))
        else:
            W, _ = make_windows(df, cfg.window, cols)
            clients.append(ClientData(i, scaler(W).astype(np.float32),
                                      np.zeros(len(W), np.int64), df))

    # --- shared eval sets ---
    Xv, _ = make_windows(val_df, cfg.window, cols)
    Xt, yt = make_windows(attack, cfg.window, cols)
    Xr, _ = make_windows(root_df, cfg.window, cols)
    Xt_s = scaler(Xt).astype(np.float32)

    # The targeted attack windows (the adversary's objective) and the other
    # attack windows, as positives-only sets: their recall is what a targeted
    # poison moves, where the global F1 over 36 diverse attacks may not.
    tmask = targeted_window_mask(len(attack), targets, cfg.window)
    tgt = (yt == 1) & tmask
    oth = (yt == 1) & ~tmask
    eval_sets = {
        "clean_val": (scaler(Xv).astype(np.float32), np.zeros(len(Xv), np.int64)),
        "test": (Xt_s, yt),
    }
    if tgt.any():
        eval_sets["test_targeted"] = (Xt_s[tgt], np.ones(int(tgt.sum()), np.int64))
    if oth.any():
        eval_sets["test_untargeted"] = (Xt_s[oth], np.ones(int(oth.sum()), np.int64))

    log.info("real federation: %d clients, %d malicious (%s), %d features, "
             "%d train windows each, %d test windows (%.3f attack); target set %d segments, "
             "%d rows, %d targeted windows",
             cfg.n_clients, n_mal, cfg.fabrication if n_mal else "none",
             len(cols), len(clients[0].train), len(Xt), float(yt.mean()),
             len(targets), target_rows, int(tgt.sum()))

    # The physics gate's own verdict on every malicious batch, so a results
    # table can show both doors: what the check admits, and what the rule admits.
    gate = [inv_set.batch_verdict(c.raw) for c in clients if c.is_malicious]

    return {
        "clients": clients,
        "columns": cols,
        "scaler": scaler,
        "invariants": inv_set,
        "invariant_report": inv_report,
        "eval_sets": eval_sets,
        "physics_verdicts": [{"client": c.client_id, "violating_fraction": v["violating_fraction"],
                              "admitted": v["admitted"]}
                             for c, v in zip([c for c in clients if c.is_malicious], gate)],
        "physics_admitted_rate": float(np.mean([v["admitted"] for v in gate])) if gate else None,
        "root_data": scaler(Xr).astype(np.float32),
        "n_malicious": n_mal,
        "test_attack_rate": float(yt.mean()),
        "target_segments": [s.tolist() for s in targets],
        "n_targeted_windows": int(tgt.sum()),
    }
