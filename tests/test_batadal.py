"""BATADAL loader and invariant set.

These tests protect against the two file quirks that would silently corrupt a
run: the leading spaces in the second file's headers, and the -999 unlabelled
marker. They are skipped automatically when the data is not present, so the
suite still passes on a machine that has not downloaded it.
"""
import sys
from pathlib import Path
import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from pafl.utils.paths import dataset_dir
    DATA = dataset_dir("batadal")
except Exception:
    DATA = Path("data/batadal")
HAVE_DATA = (DATA / "BATADAL_dataset03.csv").exists() and (DATA / "BATADAL_dataset04.csv").exists()
pytestmark = pytest.mark.skipif(not HAVE_DATA, reason=f"BATADAL CSVs not found under {DATA}")


@pytest.fixture(scope="module")
def data():
    from pafl.data.batadal import load_batadal
    return (load_batadal(DATA / "BATADAL_dataset03.csv"),
            load_batadal(DATA / "BATADAL_dataset04.csv"))


def test_headers_are_stripped(data):
    clean, atk = data
    assert all(c == c.strip() for c in clean.columns)
    assert all(c == c.strip() for c in atk.columns)
    assert "L_T1" in atk.columns and " L_T1" not in atk.columns


def test_unlabelled_rows_become_normal_not_attack(data):
    """-999 must map to 0. If it leaked through as a positive label, the attack
    rate would be absurd and every metric downstream would be wrong."""
    clean, atk = data
    assert set(np.unique(atk["ATT_FLAG"])) <= {0, 1}
    assert clean["ATT_FLAG"].sum() == 0
    assert 100 < int(atk["ATT_FLAG"].sum()) < 400        # 219 labelled attack rows


def test_clean_data_is_admitted(data):
    from pafl.data.batadal import batadal_invariants
    clean, _ = data
    inv, _ = batadal_invariants(clean)
    inv.calibrate(clean)
    assert inv.batch_verdict(clean)["admitted"]


def test_couplings_are_recovered(data):
    """The actuator-flow couplings are the exact invariants on this network.
    If the loader or classifier regresses, they vanish and the check weakens."""
    from pafl.data.batadal import batadal_invariants
    clean, _ = data
    _, rep = batadal_invariants(clean)
    assert rep["kept_couplings"] >= 4
    assert rep["kept_balances"] >= 2


def test_real_attacks_score_higher_than_normal(data):
    """The invariants must flag the genuine dataset04 attacks, not only the
    fabrications, or they are not measuring physics."""
    from pafl.data.batadal import batadal_invariants
    clean, atk = data
    inv, _ = batadal_invariants(clean)
    inv.calibrate(clean)
    score = inv.row_score(atk)
    lab = atk["ATT_FLAG"].to_numpy()
    assert score[lab == 1].mean() > 5 * score[lab == 0].mean()
