from pathlib import Path

import pytest

from autoseal.managed_repair import validate_managed_fixture, verify_managed_report
from autoseal.revisions import RevisionManager
from autoseal.result_binding import ResultContext, bind_result
from autoseal.storage import ContentAddressedStore, IntegrityError
import copy
from fastapi.testclient import TestClient
from autoseal.api import create_app


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def validation(tmp_path_factory):
    root = tmp_path_factory.mktemp("managed-validation")
    identity = validate_managed_fixture(root)
    return root, identity


def test_scoped_validation_measures_behavior_and_rollback_but_cannot_hide_missing_gates(validation):
    root, identity = validation
    store = ContentAddressedStore(root / "evidence")
    report = store.get_json(identity)
    assert report["disposition"] == "UNENFORCEABLE"
    assert {name for name, passed in report["gates"].items() if not passed} == {
        "required_stress_functional_rejection"}
    assert report["schema_version"] == 3
    assert report["gates"]["active_provider_enforcement"] is True
    assert store.get_json(report["enforcement_probe_id"])["passed"] is True
    assert len(report["controls"]) == 8
    assert sum(entry["role"] == "heldout" for entry in report["controls"]) == 2
    assert all(len(entry["sealed"]) == 3 for entry in report["controls"])
    manager = RevisionManager(root / "manager", store)
    assert manager.active() == report["parent_revision"]
    assert report["activation_id"] is None
    assert store.get_json(report["rollback_id"])["after"] == report["parent_revision"]
    assert report["unsupported_control"]["disposition"] == "UNENFORCEABLE"
    assert verify_managed_report(root, identity) == report
    assert report["run_metadata"]["evaluations"] == 42
    assert report["run_metadata"]["total_container_executions"] == 43
    for change in ("gate", "role", "repeat", "promotion", "rollback", "probe"):
        forged = copy.deepcopy(report)
        if change == "gate":
            forged["gates"]["required_stress_functional_rejection"] = True
        elif change == "role":
            forged["controls"][0]["role"] = "exploit"
        elif change == "repeat":
            forged["controls"][0]["sealed"].pop()
        elif change == "promotion":
            forged["disposition"] = "PROMOTED"
        elif change == "probe":
            forged["gates"]["active_provider_enforcement"] = False
        else:
            forged["rollback_id"] = report["restored_proxy_id"]
        with pytest.raises((IntegrityError, ValueError)):
            verify_managed_report(root, store.put_json(forged))


@pytest.mark.parametrize("change", ["raw_output", "repeat_reuse", "restored_context", "stress_context", "snapshot", "activation", "probe_context", "probe_raw"])
def test_full_report_rejects_rehashed_evidence_substitution(validation, change):
    root, identity = validation
    store = ContentAddressedStore(root / "evidence")
    report = copy.deepcopy(store.get_json(identity))
    control = report["controls"][0]
    if change == "raw_output":
        receipt = store.get_json(control["sealed"][0])
        result = store.get_json(receipt["evaluation_id"])
        result["process"]["stdout"] = "[]"
        result["process_id"] = store.put_json(result["process"])
        control["sealed"][0] = bind_result(store, ResultContext.model_validate(receipt["context"]), result)
    elif change == "repeat_reuse":
        control["sealed"][1] = control["sealed"][0]
    elif change in {"restored_context", "stress_context"}:
        key = "restored_proxy_id" if change == "restored_context" else None
        old = report[key] if key else report["unsupported_control"]["result_id"]
        receipt = store.get_json(old)
        result = store.get_json(receipt["evaluation_id"])
        receipt["context"]["task"] = "sha256:" + "f" * 64
        changed = bind_result(store, ResultContext.model_validate(receipt["context"]), result)
        if key:
            report[key] = changed
        else:
            report["unsupported_control"]["result_id"] = changed
    elif change == "snapshot":
        corpus = store.get_json(report["corpus_id"])
        corpus["cases"][0]["files"]["solution.py"] = store.put_bytes(b"different input")
        report["corpus_id"] = store.put_json(corpus)
    elif change == "activation":
        report["trial_activation_id"] = report["parent_activation_id"]
    else:
        probe = store.get_json(report["enforcement_probe_id"])
        if change == "probe_context":
            probe["context"]["environment"] = report["parent_revision"]
        else:
            import json
            process = probe["execution"]["process"]
            observed = json.loads(process["stdout"])
            observed["candidate_write_denied"] = False
            process["stdout"] = json.dumps(observed)
            probe["execution"]["process_id"] = store.put_json(process)
        report["enforcement_probe_id"] = store.put_json(probe)
    with pytest.raises(IntegrityError):
        verify_managed_report(root, store.put_json(report))


def test_api_rechecks_retained_execution_and_fails_closed_on_corrupt_bytes(validation, monkeypatch):
    root, identity = validation
    app = create_app(f"sqlite:///{root / 'view.db'}", root / "unused-store",
                     managed_report_root=root, managed_report_identity=identity)
    def forbidden(*args, **kwargs):
        raise AssertionError("viewing a retained report must not execute anything")
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("autoseal.owned_verifier.run_command", forbidden)
    with TestClient(app) as client:
        response = client.get("/api/research/managed-repair")
        assert response.status_code == 200, response.text
        view = response.json()
        assert view["source"] == "verified_saved_execution"
        assert view["run_metadata"]["evaluations"] == 42
        assert len(view["controls"]) == 8
        assert view["stress"]["verdict"] == "INCONCLUSIVE"
        assert view["seal_evidence"] is None
        assert view["enforcement_probe"]["passed"] is True
        digest = identity[7:]
        path = root / "evidence/objects" / digest[:2] / digest
        original = path.read_bytes()
        try:
            path.write_bytes(b"{}")
            failed = client.get("/api/research/managed-repair")
            assert failed.status_code == 503
            assert "integrity" in failed.json()["detail"]
        finally:
            path.write_bytes(original)
        assert client.get("/api/research/managed-repair").status_code == 200
