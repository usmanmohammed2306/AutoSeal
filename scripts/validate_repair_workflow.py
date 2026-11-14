"""Actual authenticated HTTP/worker/PostgreSQL/Docker repair and crash recovery.

Creates and removes its own disposable database only. Kills its own worker,
waits for the real lease deadline, then reclaims the job. No simulated lease
mutation, external candidate, model call or GPU allocation is used.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

import httpx

from autoseal.db import WorkflowRow, make_session_factory
from autoseal.execution import run_command
from autoseal.storage import ContentAddressedStore


POSTGRES = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
API = """
import os, sys, uvicorn
from pathlib import Path
from autoseal.api import create_app
app = create_app(os.environ['AUTOSEAL_DATABASE_URL'], Path(sys.argv[1]), workflow_root=Path(sys.argv[2]),
    operator_token=os.environ['AUTOSEAL_OPERATOR_TOKEN'], reader_token=os.environ['AUTOSEAL_READER_TOKEN'])
uvicorn.run(app, host='127.0.0.1', port=int(sys.argv[3]))
"""
WORKER = """
import json, os, sys
from pathlib import Path
from autoseal.db import make_session_factory
from autoseal.storage import ContentAddressedStore
from autoseal.workflows import WorkflowService
service = WorkflowService(make_session_factory(os.environ['AUTOSEAL_DATABASE_URL']),
    ContentAddressedStore(Path(sys.argv[1])), Path(sys.argv[2]))
row = service.process_one()
assert row is not None
print(json.dumps({'id': row.id, 'state': row.state, 'attempts': row.attempts, 'error': row.error}))
raise SystemExit(0 if row.state in {'COMPLETED', 'CANCELLED'} else 1)
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    store, workflow_root = ContentAddressedStore(args.root / "evidence"), args.root / "workflows"
    started, clock = datetime.now(timezone.utc).isoformat(), time.monotonic()
    checks, steps = {}, []
    password, operator, reader = (secrets.token_hex(32) for _ in range(3))
    db_url = ""
    env = dict(os.environ, POSTGRES_PASSWORD=password, AUTOSEAL_OPERATOR_TOKEN=operator, AUTOSEAL_READER_TOKEN=reader)
    container, api, workers, identities = "autoseal-repair-e2e-" + uuid.uuid4().hex, None, [], []
    status, error = "FAILED", None

    def redact(value):
        for secret in (db_url, password, operator, reader):
            if secret:
                value = value.replace(secret, "[redacted]")
        return value

    def command(argv, *, required=True, timeout=30):
        result = run_command(argv, env=env, timeout_seconds=timeout)
        raw = result.to_dict()
        raw["stdout"], raw["stderr"] = redact(raw["stdout"]), redact(raw["stderr"])
        steps.append({"process_id": store.put_json(raw)})
        if required and result.exit_code != 0:
            raise RuntimeError("validation command failed; see retained receipt")
        return result

    with tempfile.TemporaryFile() as api_log, tempfile.TemporaryFile() as worker_log:
        def worker():
            process = subprocess.Popen([sys.executable, "-c", WORKER, str(store.root.resolve()), str(workflow_root.resolve())],
                env=env, stdin=subprocess.DEVNULL, stdout=worker_log, stderr=worker_log, start_new_session=True)
            workers.append(process)
            return process

        def finish(process):
            code = process.wait(timeout=120)
            if code != 0:
                raise RuntimeError("repair worker failed; see retained worker log")

        try:
            command(["docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES])
            command(["docker", "run", "-d", "--name", container, "--label", "autoseal.validation=true",
                "--memory", "512m", "--cpus", "1", "--pids-limit", "128", "--tmpfs", "/var/lib/postgresql/data:rw,size=256m",
                "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_USER=autoseal_e2e",
                "-e", "POSTGRES_DB=autoseal_e2e", POSTGRES])
            port = command(["docker", "port", container, "5432/tcp"]).stdout.strip().rsplit(":", 1)[1]
            db_url = f"postgresql+psycopg://autoseal_e2e:{password}@127.0.0.1:{port}/autoseal_e2e"
            env["AUTOSEAL_DATABASE_URL"] = db_url
            for _ in range(50):
                if command(["docker", "exec", container, "pg_isready", "-U", "autoseal_e2e"], required=False).exit_code == 0:
                    break
                time.sleep(.2)
            command([sys.executable, "-m", "alembic", "upgrade", "head"])
            command([sys.executable, "-m", "alembic", "downgrade", "base"])
            command([sys.executable, "-m", "alembic", "upgrade", "head"])
            checks["real_migration_upgrade_downgrade_upgrade"] = True
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0)); api_port = listener.getsockname()[1]
            api = subprocess.Popen([sys.executable, "-c", API, str(store.root.resolve()), str(workflow_root.resolve()), str(api_port)],
                env=env, stdin=subprocess.DEVNULL, stdout=api_log, stderr=api_log, start_new_session=True)
            with httpx.Client(base_url=f"http://127.0.0.1:{api_port}", timeout=45) as client:
                for _ in range(100):
                    try:
                        if client.get("/api/health").status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    if api.poll() is not None:
                        raise RuntimeError("API failed before readiness")
                    time.sleep(.1)
                else:
                    raise RuntimeError("API readiness deadline exceeded")

                def request(method, path, expected=200, payload=None):
                    response = client.request(method, path, json=payload)
                    body = response.json()
                    steps.append({"http_id": store.put_json({"method": method, "path": path,
                        "request": payload, "status": response.status_code, "response": body})})
                    assert response.status_code == expected, f"HTTP {response.status_code} at {path}"
                    return body

                request("GET", "/api/workflows", 401)
                client.headers["Authorization"] = "Bearer " + reader
                request("POST", "/api/workflows", 403, {})
                request("GET", "/api/research/repair-preview", 403)
                request("GET", "/api/cases")
                client.headers["Authorization"] = "Bearer " + operator
                checks["authentication_and_reader_mutation_denial"] = True

                def submit(kind, payload, key=None):
                    row = request("POST", "/api/workflows", 202, {"kind": kind, "payload": payload,
                        "idempotency_key": key or uuid.uuid4().hex})
                    identities.append(row["id"])
                    return row

                job = submit("artifact_validate", {"case": "artifact-skip_hook-0"}, "crash-recovery")
                assert submit("artifact_validate", {"case": "artifact-skip_hook-0"}, "crash-recovery")["id"] == job["id"]
                first = worker()
                # Wait for a real container owned by this first worker attempt.
                for _ in range(400):
                    listed = command(["docker", "ps", "-aq", "--filter", f"label=autoseal.scope={job['id']}.1"])
                    if listed.stdout.strip():
                        break
                    if first.poll() is not None:
                        raise RuntimeError("worker completed before the crash could be injected")
                    time.sleep(.05)
                else:
                    raise RuntimeError("owned runtime container was not observed")
                os.killpg(first.pid, signal.SIGKILL)
                assert first.wait(timeout=5) == -signal.SIGKILL
                steps.append({"fault": "SIGKILL of this validation's worker process group", "workflow_id": job["id"],
                              "owned_container_inventory_id": store.put_json(listed.to_dict())})
                sessions = make_session_factory(db_url)
                for _ in range(650):
                    with sessions() as session:
                        row = session.get(WorkflowRow, job["id"])
                        expired = row.lease_expires_at <= datetime.now(timezone.utc)
                    if expired:
                        break
                    time.sleep(.2)
                else:
                    raise RuntimeError("natural lease expiry deadline exceeded")
                finish(worker())
                row = request("GET", f"/api/workflows/{job['id']}")
                assert row["state"] == "COMPLETED" and row["attempts"] == 2
                events = request("GET", f"/api/workflows/{job['id']}/events")
                assert any(e["kind"] == "PREVIOUS_ATTEMPT_CLEANED" for e in events)
                assert not command(["docker", "ps", "-aq", "--filter", f"label=autoseal.scope={job['id']}.1"]).stdout.strip()
                checks["actual_sigkill_natural_lease_reclaim_and_owned_container_cleanup"] = True
                checks["transactional_idempotency"] = True
                validation = request("GET", f"/api/workflows/{job['id']}/validation")
                assert all(validation["gates"].values())
                checks["measured_preservation_and_raw_receipt_verification"] = True

                def execute(kind, **extra):
                    row = submit(kind, {"validation_job_id": job["id"], **extra})
                    finish(worker())
                    assert request("GET", f"/api/workflows/{row['id']}")["state"] == "COMPLETED"
                    return request("GET", f"/api/workflows/{row['id']}/result")

                assert execute("artifact_promote")["disposition"] == "PROMOTED"
                assert execute("artifact_replay", candidate="exploit")["verdict"] == "REJECT"
                assert execute("artifact_rollback")["restored_revision"] == validation["parent_revision"]
                assert execute("artifact_replay", candidate="exploit")["verdict"] == "PASS"
                execute("artifact_promote")
                checks["guarded_promotion_fresh_replay_verified_rollback_and_repromotion"] = True

                cancelled = submit("artifact_validate", {"case": "artifact-skip_hook-1"})
                process = worker()
                for _ in range(100):
                    if request("GET", f"/api/workflows/{cancelled['id']}")["state"] == "RUNNING":
                        break
                    time.sleep(.05)
                request("POST", f"/api/workflows/{cancelled['id']}/cancel")
                finish(process)
                assert request("GET", f"/api/workflows/{cancelled['id']}")["state"] == "CANCELLED"
                checks["running_cancellation_cleanup_acknowledged"] = True
                status = "PASSED"
        except Exception as exc:
            error = redact(f"{type(exc).__name__}: {exc}")
        finally:
            for process in [*workers, api]:
                if process is not None and process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=5)
            from autoseal.workflows import cleanup_scope
            try:
                for identity in set(identities):
                    for attempt in range(1, 4):
                        steps.append({"final_cleanup_id": cleanup_scope(store, f"{identity}.{attempt}")})
                checks["all_validation_container_scopes_cleaned"] = True
            except Exception as exc:
                checks["all_validation_container_scopes_cleaned"] = False
                error = error or redact(str(exc))
            checks["owned_database_removed"] = command(["docker", "rm", "-f", container], required=False).exit_code == 0
            api_log.seek(0); worker_log.seek(0)
            logs = {"api": store.put_bytes(redact(api_log.read().decode(errors="replace")).encode()),
                    "worker": store.put_bytes(redact(worker_log.read().decode(errors="replace")).encode())}
    if not all(checks.values()):
        status = "FAILED"
    sources = {str(p): store.put_bytes(p.read_bytes()) for p in sorted(Path("src/autoseal").glob("*.py"))}
    sources[__file__] = store.put_bytes(Path(__file__).read_bytes())
    report = {"kind": "authenticated_repair_workflow_e2e", "schema_version": 1, "status": status,
        "error": error, "checks": checks, "steps": steps, "logs": logs, "sources": sources,
        "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - clock,
        "limitations": ["One authored seeded fixed-output case, not an external benchmark or model study.",
                        "Loopback HTTP bearer authentication; public TLS/deployment is not tested.",
                        "A real worker SIGKILL and natural lease expiry; the entire host was not crashed."]}
    identity = store.put_json(report)
    (args.root / "report.json").write_text(json.dumps({"report_id": identity}, indent=2) + "\n")
    print(json.dumps({"report_id": identity, "status": status, "checks": checks, "error": error}, indent=2))
    return 0 if status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
