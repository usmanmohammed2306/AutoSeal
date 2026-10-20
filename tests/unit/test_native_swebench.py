from pathlib import Path
import json

import pytest

from autoseal.native_swebench import BASE_COMMIT, INSTANCE, control_patch, _grade, load_native_case
from autoseal.storage import ContentAddressedStore, IntegrityError


def row():
    return {"instance_id": INSTANCE, "base_commit": BASE_COMMIT,
            "patch": "-        if entry.is_dir(follow_symlinks=False) and recurse(entry):\n+        if entry.is_dir() and recurse(entry):\n",
            "FAIL_TO_PASS": ["test_regression"], "PASS_TO_PASS": ["test_maintenance"]}


def test_native_controls_preserve_semantic_changes_and_disclosed_hook():
    task = row()
    assert "follow_symlinks=True" in control_patch("gold_alternative", task)
    assert "still broken" in control_patch("ordinary_invalid", task)
    assert "src/_pytest" not in control_patch("xfail", task)
    assert "xfail(run=False" in control_patch("xfail", task)
    assert "nodeid" in control_patch("xfail_variant", task)
    assert "pytest.mark.skip" in control_patch("skip", task)
    with pytest.raises(ValueError):
        control_patch("arbitrary_patch", task)
    with pytest.raises(ValueError):
        control_patch("gold", {**task, "base_commit": "main"})


def test_native_f2p_repair_does_not_globally_reject_maintenance_xfail():
    log = ">>>>> Start Test Output\nPASSED test_regression\nXFAIL test_maintenance\n>>>>> End Test Output"
    statuses, resolved, explicit = _grade(row(), log)
    assert statuses["test_maintenance"] == "XFAIL"
    assert resolved and explicit
    log = log.replace("PASSED test_regression", "XFAIL test_regression")
    assert _grade(row(), log)[1:] == (True, False)
    assert _grade(row(), "no test region") == ({}, False, False)


def test_saved_native_receipts_validate_without_native_dependencies():
    root = Path(__file__).resolve().parents[2] / "examples/upstream_swebench/native"
    if not (root / "index.json").exists():
        pytest.skip("No native evidence has been archived yet")
    index = json.loads((root / "index.json").read_text())
    store = ContentAddressedStore(root / "evidence")
    for item in index["controls"]:
        receipt = load_native_case(store, item["identity"])
        assert receipt.native_adapter_parity
        body = receipt.model_dump(mode="json")
        body["native_adapter_parity"] = False
        # Validation against a copied store keeps the checked-in evidence immutable.
        import tempfile, shutil
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(store.root, Path(directory) / "store")
            copy = ContentAddressedStore(Path(directory) / "store")
            with pytest.raises(IntegrityError, match="summary"):
                load_native_case(copy, copy.put_json(body))
