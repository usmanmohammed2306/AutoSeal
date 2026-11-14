"""Registered intent, access policy and the real persisted repair lifecycle."""

from pathlib import Path
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import event

from autoseal.api import create_app
from autoseal.db import Base, WorkflowRow
from autoseal.storage import ContentAddressedStore


OPERATOR, READER = "operator-" + "a" * 48, "reader-" + "b" * 48


def app_for(root):
    app = create_app(f"sqlite:///{root / 'workflow.db'}", root / "evidence",
                     operator_token=OPERATOR, reader_token=READER)
    engine = app.state.run_service.sessions.kw["bind"]
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    return app


def submit(client, kind="artifact_validate", payload=None, key=None):
    return client.post("/api/workflows", json={"kind": kind,
        "payload": payload or {"case": "artifact-skip_hook-0"}, "idempotency_key": key or uuid.uuid4().hex})


def test_access_denial_covers_mutations_evidence_events_and_legacy_execution(tmp_path):
    app = app_for(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        for path in ("/api/workflows", "/api/runs", "/api/cases", "/api/research/training-pilots", "/docs"):
            assert client.get(path).status_code == 401
        client.headers["Authorization"] = "Bearer " + READER
        assert client.get("/api/access").json()["role"] == "reader"
        assert client.get("/api/cases").status_code == 200
        assert submit(client).status_code == 403
        assert client.get("/api/research/repair-preview").status_code == 403
        assert client.get("/api/research/fixtures/exploit/influence").status_code == 403
        client.headers["Authorization"] = "Bearer " + OPERATOR
        row = submit(client).json()
        client.headers["Authorization"] = "Bearer " + READER
        assert client.post(f"/api/workflows/{row['id']}/cancel").status_code == 403
        assert client.get(f"/api/workflows/{row['id']}/events").status_code == 200
        assert client.get(f"/api/workflows/{row['id']}/result").status_code == 404
        client.headers.clear()
        assert client.get(f"/api/workflows/{row['id']}/stream").status_code == 401
        assert client.get(f"/api/workflows/{row['id']}/result").status_code == 401


def test_closed_payload_idempotency_cancel_stream_and_request_budget(tmp_path):
    app = app_for(tmp_path)
    with TestClient(app, headers={"Authorization": "Bearer " + OPERATOR}) as client:
        first = submit(client, key="same").json()
        assert submit(client, key="same").json()["id"] == first["id"]
        assert submit(client, key="same", payload={"case": "artifact-skip_hook-1"}).status_code == 400
        for kind, payload in (("shell", {"command": ["whoami"]}),
                              ("artifact_validate", {"case": "../../tmp"}),
                              ("artifact_validate", {"case": "artifact-skip_hook-0", "root": "/tmp"}),
                              ("artifact_promote", {"validation_job_id": str(uuid.uuid4())})):
            assert submit(client, kind, payload).status_code == 400
        assert client.get("/api/workflows/not-a-uuid").status_code == 400
        identity = first["id"]
        assert client.post(f"/api/workflows/{identity}/cancel").json()["state"] == "CANCELLED"
        assert client.post(f"/api/workflows/{identity}/retry").status_code == 409
        assert app.state.workflow_service.process_one() is None
        stream = client.get(f"/api/workflows/{identity}/stream").text
        assert '"kind": "CANCELLED"' in stream
        assert client.post("/api/workflows", content=b"x" * 65537).status_code == 413
        assert len(client.get("/api/workflows").json()) == 1


def test_lease_fencing_and_atomic_mutation_cancellation(tmp_path):
    app = app_for(tmp_path)
    service = app.state.workflow_service
    row = service.submit("artifact_validate", {"case": "artifact-skip_hook-0"}, "lease")
    with service.sessions() as session:
        saved = session.get(WorkflowRow, row.id)
        saved.state, saved.lease_token = "RUNNING", "current-owner"
        session.commit()
    with pytest.raises(RuntimeError, match="lease"):
        service._heartbeat(row.id, "old-owner")
    service.cancel(row.id)
    from autoseal.workflows import WorkflowCancelled
    with pytest.raises(WorkflowCancelled):
        service._heartbeat(row.id, "current-owner")
    service._heartbeat(row.id, "current-owner", allow_cancel=True)
    with service.sessions() as session:
        saved = session.get(WorkflowRow, row.id)
        saved.kind, saved.state = "artifact_promote", "RUNNING"
        session.commit()
    with pytest.raises(ValueError, match="atomic"):
        service.cancel(row.id)


@pytest.mark.docker
def test_real_workflow_validate_promote_replay_rollback_and_corruption_refusal(tmp_path):
    app = app_for(tmp_path)
    service = app.state.workflow_service
    with TestClient(app, headers={"Authorization": "Bearer " + OPERATOR}) as client:
        validation = submit(client).json()
        processed = service.process_one()
        assert processed.state == "COMPLETED", processed.error
        view = client.get(f"/api/workflows/{validation['id']}/validation")
        assert view.status_code == 200, view.text
        assert all(view.json()["gates"].values())
        assert len(view.json()["controls"]) == 8

        def execute(kind, **extra):
            request = submit(client, kind, {"validation_job_id": validation["id"], **extra})
            assert request.status_code == 202, request.text
            row = service.process_one()
            assert row.state == "COMPLETED", row.error
            return client.get(f"/api/workflows/{row.id}/result").json()

        promotion = execute("artifact_promote")
        assert promotion["seal_evidence_id"].startswith("sha256:")
        assert execute("artifact_replay", candidate="exploit")["verdict"] == "REJECT"
        rollback = execute("artifact_rollback")
        assert rollback["restored_revision"] == view.json()["parent_revision"]
        assert execute("artifact_replay", candidate="exploit")["verdict"] == "PASS"
        execute("artifact_promote")
        result = service.result(validation["id"])
        store = ContentAddressedStore(service.root / validation["id"] / "1" / "evidence")
        path = store._path(result["validation_id"])
        original = path.read_bytes()
        path.write_bytes(b"{}")
        assert client.get(f"/api/workflows/{validation['id']}/validation").status_code == 500
        assert submit(client, "artifact_promote", {"validation_job_id": validation["id"]}).status_code == 400
        path.write_bytes(original)
        assert client.get(f"/api/workflows/{validation['id']}/validation").status_code == 200
