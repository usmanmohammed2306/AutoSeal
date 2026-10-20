import json
from pathlib import Path
import subprocess
import sys

from autoseal.evaluation import compare_fixture
from autoseal.storage import ContentAddressedStore, IntegrityError, load_comparison, store_comparison


ROOT = Path(__file__).resolve().parents[2]


def test_comparison_round_trip_and_candidate_binding(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    original = compare_fixture("exploit")
    manifest_id = store_comparison(store, original)
    recovered = load_comparison(store, manifest_id)
    assert recovered == original
    assert recovered.classification == "FALSE_REWARD"


def test_comparison_rejects_corrupt_evaluator_blob(tmp_path: Path) -> None:
    store = ContentAddressedStore(tmp_path)
    manifest_id = store_comparison(store, compare_fixture("exploit"))
    manifest = store.get_json(manifest_id)
    store._path(manifest["audit_object"]).write_bytes(b"wrong")
    try:
        load_comparison(store, manifest_id)
    except IntegrityError:
        pass
    else:
        raise AssertionError("corrupted audit evidence was accepted")


def test_cli_persist_and_replay(tmp_path: Path) -> None:
    saved = subprocess.run(
        [sys.executable, "-m", "autoseal", "compare", "exploit", "--store", str(tmp_path)],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )
    assert saved.returncode == 0, saved.stderr
    manifest_id = json.loads(saved.stdout)["manifest_id"]
    replayed = subprocess.run(
        [sys.executable, "-m", "autoseal", "replay", manifest_id, "--store", str(tmp_path)],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )
    assert replayed.returncode == 0, replayed.stderr
    assert json.loads(replayed.stdout)["classification"] == "FALSE_REWARD"
