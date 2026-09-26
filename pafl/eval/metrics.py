"""Detection metrics at one fixed, clean-calibrated alarm threshold.

fl.train calls `threshold_from_clean` once per run (the 0.995 quantile of the
final model's clean-validation scores) and `detection_report` plus
`detection_delay` on every eval set at that threshold. Scores and labels are
per window; a window is an attack window when any of its rows is labelled.

The paper argues from recall: targeted-attack recall is `detection_report`'s
"recall" on the positives-only `test_targeted` set that fl.scenario_real builds,
and the damage an attack does is the drop in that recall against the
honest-only federation (scripts/summarize_adaptive.py). Global F1 on the full
test set is reported beside it. `attack_success` is the pilot's measure, F1
drop against the clean federation, still used by scripts/sim_defences.py and
scripts/sweep.py.
"""
from __future__ import annotations
import numpy as np


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def threshold_from_clean(scores_clean: np.ndarray, quantile: float = 0.995) -> float:
    """Set the alarm threshold on clean validation data only.

    Using test data to pick the threshold inflates every number that follows,
    and reviewers of anomaly-detection papers look for exactly this mistake.
    np.quantile's default linear interpolation; at 0.995 about 0.5 % of clean
    validation windows sit above the threshold by construction.
    """
    return float(np.quantile(scores_clean, quantile))


def detection_report(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    """Confusion counts, precision, recall and F1 at `threshold`, with AUC-PR and
    the best-threshold F1 alongside as threshold-free views.

    A window alarms when its score is strictly above the threshold. On a set
    with only attack windows, recall is the one meaningful number.
    """
    pred = (scores > threshold).astype(int)
    tp = int(((pred == 1) & (labels == 1)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())
    tn = int(((pred == 0) & (labels == 0)).sum())
    p, r, f1 = _prf(tp, fp, fn)
    best = f1_best(scores, labels)
    return {"precision": p, "recall": r, "f1": f1,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "auc_pr": auc_pr(scores, labels),
            "f1_best": best["f1_best"], "threshold_best": best["threshold_best"]}


def f1_best(scores: np.ndarray, labels: np.ndarray) -> dict:
    """The best F1 over every threshold, and the threshold that gives it.

    This is the optimistic number most SWaT papers report. It is not the
    operating point a deployed detector has, so it never replaces the fixed
    clean-calibrated threshold above; it sits beside it as the threshold-free
    view, the same way AUC-PR does. On a set with no negatives or no positives
    it is undefined.

    Unlike `detection_report`, the returned threshold is inclusive (the k-th
    highest score is itself flagged), and tied scores are split by sort order.
    """
    n_pos = int(labels.sum())
    if n_pos == 0 or n_pos == len(labels):
        return {"f1_best": float("nan"), "threshold_best": float("nan")}
    order = np.argsort(-scores)
    y = labels[order]
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / n_pos
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    k = int(np.argmax(f1))
    return {"f1_best": float(f1[k]), "threshold_best": float(scores[order][k])}


def auc_pr(scores: np.ndarray, labels: np.ndarray) -> float:
    """Area under the precision-recall curve as average precision: the sum over
    ranks of the recall step times the precision there. NaN on a set with no
    negatives or no positives."""
    if labels.sum() == 0 or labels.sum() == len(labels):
        return float("nan")
    order = np.argsort(-scores)
    y = labels[order]
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / max(int(labels.sum()), 1)
    return float(np.sum(np.diff(np.concatenate([[0.0], rec])) * prec))


def detection_delay(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict:
    """Windows between the start of each attack and the first alarm inside it.

    An attack with no alarm anywhere inside it counts as missed and contributes
    no delay, so a detector that finds one attack quickly and misses nine does
    not get to report a good mean delay.

    Windows advance one row at a time, so a delay in windows is a delay in rows:
    5 s each on SWaT and WADI at the loaders' 5 s stride, 1 h on BATADAL. A
    segment is a run of consecutive attack-labelled windows, so the labels must
    be in time order; on the positives-only sets the whole set is one segment
    and the delay is not meaningful.
    """
    pred = scores > threshold
    segments: list[tuple[int, int]] = []
    in_att, start = False, 0
    for i, l in enumerate(labels):
        if l and not in_att:
            in_att, start = True, i
        elif not l and in_att:
            segments.append((start, i))
            in_att = False
    if in_att:
        segments.append((start, len(labels)))

    delays, missed = [], 0
    for a, b in segments:
        seg = pred[a:b]
        if seg.any():
            delays.append(int(np.argmax(seg)))
        else:
            missed += 1
    return {"mean_delay_windows": float(np.mean(delays)) if delays else float("nan"),
            "median_delay_windows": float(np.median(delays)) if delays else float("nan"),
            "attacks_detected": len(delays),
            "attacks_missed": missed,
            "n_attack_segments": len(segments)}


def attack_success(f1_clean_federation: float, f1_poisoned_federation: float) -> dict:
    """How much detection the poisoning removed.

    Reported in absolute F1 points, because that is what the pilot's go/no-go
    criterion was written in, and as a relative fraction. The paper's damage
    measure is on targeted recall against the honest-only run instead (see the
    module docstring).
    """
    drop = f1_clean_federation - f1_poisoned_federation
    return {"f1_drop_absolute": float(drop),
            "f1_drop_relative": float(drop / f1_clean_federation) if f1_clean_federation else 0.0}
