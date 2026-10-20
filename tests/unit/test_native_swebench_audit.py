from pathlib import Path
import json

import pytest

from autoseal.native_swebench_audit import _interpret, load_native_audit, source_projection
from autoseal.storage import ContentAddressedStore, IntegrityError


def test_audit_interpretation_is_fail_closed():
    good = {"schema_version": 1, "checks": {"symlink_directory_descended": True,
            "regular_directory_descended": True, "recurse_predicate_respected": True},
            "observed": ["link/leaf.txt", "target/leaf.txt"]}
    assert _interpret(0, json.dumps(good).encode())[1] == "PASS"
    good["checks"]["symlink_directory_descended"] = False
    assert _interpret(1, json.dumps(good).encode())[1] == "REJECT"
    assert _interpret(0, json.dumps(good).encode())[1] == "INCONCLUSIVE"
    good["checks"]["regular_directory_descended"] = False
    assert _interpret(1, json.dumps(good).encode())[1] == "INCONCLUSIVE"
    assert _interpret(None, b"")[1] == "INCONCLUSIVE"


def test_audit_source_projection_excludes_candidate_test_hook():
    hook = "diff --git a/testing/conftest.py b/testing/conftest.py\n"
    assert source_projection("xfail", hook) == ""
    assert source_projection("skip", hook) == ""
    with pytest.raises(IntegrityError):
        source_projection("xfail", "")
    with pytest.raises(ValueError):
        source_projection("unknown", hook)


def test_saved_audits_bind_to_native_candidates_and_raw_process():
    root = Path(__file__).resolve().parents[2] / "examples/upstream_swebench/native"
    index = json.loads((root / "audit_index.json").read_text())
    native_index = json.loads((root / "index.json").read_text())
    native = {item["case"]: item["identity"] for item in native_index["controls"]}
    store = ContentAddressedStore(root / "evidence")
    for item in index["controls"]:
        receipt = load_native_audit(store, item["identity"])
        assert receipt.native_receipt_id == native[item["case"]]
        assert receipt.verdict == item["verdict"]
        assert receipt.verdict != "INCONCLUSIVE"
