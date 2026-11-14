"""Offline linkage and tamper checks for the retained external task replay."""

import copy
import json
from pathlib import Path

import pytest

from autoseal.native_shell_archive import load_shell_archive, verify_shell_report
from autoseal.storage import ContentAddressedStore, IntegrityError


ROOT = Path(__file__).resolve().parents[2] / "research/experiments/2026-11-13-artifact-admission/external-shell-attempt-01"
pytestmark = pytest.mark.archive


@pytest.fixture
def archive():
    if not (ROOT / "report.json").exists():
        pytest.skip("separately retained native-test archive not available")
    store = ContentAddressedStore(ROOT / "evidence")
    identity = json.loads((ROOT / "report.json").read_text())["report_id"]
    return store, identity


def test_actual_native_test_controls_and_independent_audit(archive):
    view = load_shell_archive(ROOT)
    assert len(view["controls"]) == 8
    assert [c["audit"] for c in view["controls"]] == ["PASS", "PASS", *(["REJECT"] * 6)]
    assert all(c["proxy"] == "PASS" and c["sealed"] == "REJECT" for c in view["controls"][4:])


def test_pinned_api_read_and_wrong_identity_refusal(archive, tmp_path):
    from fastapi.testclient import TestClient
    from autoseal.api import create_app
    _, identity = archive
    app = create_app(f"sqlite:///{tmp_path / 'api.db'}", tmp_path / 'evidence',
        shell_archive_root=ROOT, shell_archive_identity=identity, operator_token='a' * 32, reader_token='b' * 32)
    with TestClient(app, headers={'Authorization': 'Bearer ' + 'b' * 32}) as client:
        response = client.get('/api/research/terminal-shell')
        assert response.status_code == 200
        assert response.json()['report_id'] == identity
    app = create_app(f"sqlite:///{tmp_path / 'wrong.db'}", tmp_path / 'wrong',
        shell_archive_root=ROOT, shell_archive_identity='sha256:' + '0' * 64)
    with TestClient(app) as client:
        assert client.get('/api/research/terminal-shell').status_code == 503


@pytest.mark.parametrize("change", ["candidate", "summary", "source", "worker", "lifecycle", "missing"])
def test_forged_summary_or_linkage_is_refused(archive, change):
    store, identity = archive
    report = copy.deepcopy(store.get_json(identity))
    if change == "missing":
        report["rows"].pop()
    elif change == "source":
        report["source_revision"] = "0" * 40
    elif change == "summary":
        report["rows"][4]["channels"]["audit"]["verdict"] = "PASS"
    else:
        ref = report["rows"][4]["channels"]["audit"]
        receipt = copy.deepcopy(store.get_json(ref["identity"]))
        if change == "candidate":
            receipt["candidate_id"] = store.get_json(report["corpus_id"])["controls"][0]["candidate_id"]
        elif change == "worker":
            receipt["worker_id"] = store.put_bytes(b"print('PASS')")
        else:
            receipt["raw"]["cleanup"] = receipt["raw"]["create"]
        ref["identity"] = store.put_json(receipt)
    with pytest.raises((IntegrityError, ValueError, KeyError)):
        verify_shell_report(store, store.put_json(report))
