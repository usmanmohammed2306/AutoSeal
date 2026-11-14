"""Exercise actual HTTP, separate workers, PostgreSQL and Docker locally.

Uses a disposable database container from the already cached pinned image.
Never touches an existing database or requests Sol/GPU resources. The supplied
managed report is read-only. Run from the repository root with the project venv.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
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

from autoseal.db import RunRow, make_session_factory
from autoseal.execution import run_command
from autoseal.storage import ContentAddressedStore


POSTGRES = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
API_CODE = """
import os, sys, uvicorn
from pathlib import Path
from autoseal.api import create_app
app = create_app(os.environ['AUTOSEAL_DATABASE_URL'], Path(sys.argv[1]),
    managed_report_root=Path(sys.argv[2]), managed_report_identity=sys.argv[3])
uvicorn.run(app, host='127.0.0.1', port=int(sys.argv[4]))
"""
WORKER_CODE = """
import json, os, sys
from pathlib import Path
from autoseal.db import make_session_factory
from autoseal.service import RunService
from autoseal.storage import ContentAddressedStore
service = RunService(make_session_factory(os.environ['AUTOSEAL_DATABASE_URL']), ContentAddressedStore(Path(sys.argv[1])))
row = service.process_one()
assert row is not None
print(json.dumps({'id': row.id, 'state': row.state, 'attempts': row.attempts}))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="New evidence directory; never reused.")
    parser.add_argument("--managed-root", type=Path, required=True)
    parser.add_argument("--managed-id", required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.root / "evidence")
    steps, checks, runs = [], {}, []
    started, clock = datetime.now(timezone.utc).isoformat(), time.monotonic()
    container = "autoseal-e2e-" + uuid.uuid4().hex
    api = None
    password = secrets.token_hex(24)
    previous = {k: os.environ.get(k) for k in ("POSTGRES_PASSWORD", "AUTOSEAL_DATABASE_URL")}
    os.environ["POSTGRES_PASSWORD"] = password
    database_url = ""
    status, error = "FAILED", None

    def clean(text):
        return text.replace(database_url, "[database-url]") .replace(password, "[password]") if database_url else text.replace(password, "[password]")

    def command(argv, *, timeout=30, required=True):
        process = run_command(argv, timeout_seconds=timeout)
        raw = process.to_dict()
        raw["stdout"], raw["stderr"] = clean(raw["stdout"]), clean(raw["stderr"])
        steps.append({"command_id": store.put_json(raw)})
        if required and process.exit_code != 0:
            raise RuntimeError(f"command failed: {argv[:3]} (see retained receipt)")
        return process

    with tempfile.TemporaryFile() as api_log:
        try:
            command(["docker", "image", "inspect", "--format", "{{.Id}}", POSTGRES])
            command(["docker", "run", "-d", "--name", container, "--label", "autoseal.validation=true",
                "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
                "--tmpfs", "/var/lib/postgresql/data:rw,size=256m", "-p", "127.0.0.1::5432",
                "-e", "POSTGRES_PASSWORD", "-e", "POSTGRES_USER=autoseal_e2e",
                "-e", "POSTGRES_DB=autoseal_e2e", POSTGRES])
            port = command(["docker", "port", container, "5432/tcp"]).stdout.strip().rsplit(":", 1)[1]
            database_url = f"postgresql+psycopg://autoseal_e2e:{password}@127.0.0.1:{port}/autoseal_e2e"
            os.environ["AUTOSEAL_DATABASE_URL"] = database_url
            for _ in range(30):
                ready = command(["docker", "exec", container, "pg_isready", "-U", "autoseal_e2e"], required=False)
                if ready.exit_code == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("disposable PostgreSQL did not become ready")
            command([sys.executable, "-m", "alembic", "upgrade", "head"])
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                api_port = listener.getsockname()[1]
            api = subprocess.Popen([sys.executable, "-c", API_CODE, str(store.root.resolve()),
                str(args.managed_root.resolve()), args.managed_id, str(api_port)],
                stdin=subprocess.DEVNULL, stdout=api_log, stderr=api_log, start_new_session=True)
            with httpx.Client(base_url=f"http://127.0.0.1:{api_port}", timeout=30) as client:
                for _ in range(100):
                    try:
                        if client.get("/api/health").status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    if api.poll() is not None:
                        raise RuntimeError("API exited before readiness")
                    time.sleep(0.1)
                else:
                    raise RuntimeError("API readiness deadline exceeded")

                def request(method, path, expected, payload=None):
                    response = client.request(method, path, json=payload)
                    body = response.json()
                    steps.append({"http_id": store.put_json({"method": method, "path": path,
                        "request": payload, "status": response.status_code, "response": body})})
                    if response.status_code != expected:
                        raise RuntimeError(f"unexpected HTTP status {response.status_code} for {path}")
                    return body

                for candidate, classification in (("positive", "AGREEMENT_PASS"),
                        ("negative", "AGREEMENT_REJECT"), ("exploit", "FALSE_REWARD")):
                    key = uuid.uuid4().hex
                    row = request("POST", "/api/runs", 202, {"candidate": candidate, "idempotency_key": key})
                    same = request("POST", "/api/runs", 202, {"candidate": candidate, "idempotency_key": key})
                    assert same["id"] == row["id"]
                    request("POST", "/api/runs", 400, {"candidate": "positive_alternative", "idempotency_key": key})
                    request("GET", f"/api/runs/{row['id']}/evidence", 404)
                    command([sys.executable, "-c", WORKER_CODE, str(store.root.resolve())])
                    finished = request("GET", f"/api/runs/{row['id']}", 200)
                    assert finished["state"] == "COMPLETED" and finished["classification"] == classification
                    evidence = request("GET", f"/api/runs/{row['id']}/evidence", 200)
                    assert store.get_json(finished["manifest_id"]) == evidence
                    assert evidence["proxy"]["candidate_identity"] == evidence["audit"]["candidate_identity"]
                    events = request("GET", f"/api/runs/{row['id']}/events", 200)
                    assert [event["kind"] for event in events] == ["QUEUED", "RUNNING", "COMPLETED"]
                    runs.append(finished)
                checks["real_http_worker_postgres_docker_controls"] = True
                checks["idempotency_and_conflicts"] = True

                row = request("POST", "/api/runs", 202, {"candidate": "positive_alternative"})
                sessions = make_session_factory(database_url)
                with sessions() as session:
                    claimed = session.get(RunRow, row["id"])
                    claimed.state, claimed.attempts, claimed.lease_token = "RUNNING", 1, "fault-injected-expired-lease"
                    claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
                    session.commit()
                steps.append({"fault": "Injected expired RUNNING lease to simulate a lost worker; no real process crash claimed.", "run_id": row["id"]})
                command([sys.executable, "-c", WORKER_CODE, str(store.root.resolve())])
                recovered = request("GET", f"/api/runs/{row['id']}", 200)
                assert recovered["state"] == "COMPLETED" and recovered["attempts"] == 2
                checks["expired_lease_recovery"] = True

                view = request("GET", "/api/research/managed-repair", 200)
                assert view["report_id"] == args.managed_id and view["seal_evidence"] is None
                assert view["disposition"] == "UNENFORCEABLE" and len(view["controls"]) == 8
                checks["pinned_managed_validation_view"] = True
                digest = runs[-1]["manifest_id"][7:]
                path = store.root / "objects" / digest[:2] / digest
                original = path.read_bytes()
                try:
                    path.write_bytes(b"{}")
                    request("GET", f"/api/runs/{runs[-1]['id']}/evidence", 500)
                finally:
                    path.write_bytes(original)
                request("GET", f"/api/runs/{runs[-1]['id']}/evidence", 200)
                checks["corrupt_evidence_refused_then_restored"] = True
                request("POST", "/api/runs", 400, {"candidate": "../../etc"})
                checks["unsupported_input_refused"] = True
                status = "PASSED"
        except Exception as exc:
            error = clean(f"{type(exc).__name__}: {exc}")
        finally:
            if api is not None and api.poll() is None:
                os.killpg(api.pid, signal.SIGTERM)
                try:
                    api.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(api.pid, signal.SIGKILL)
                    api.wait(timeout=5)
            cleanup = command(["docker", "rm", "-f", container], required=False)
            checks["owned_database_removed"] = cleanup.exit_code == 0
            api_log.seek(0)
            api_log_id = store.put_bytes(clean(api_log.read().decode("utf-8", errors="replace")).encode())
            for key, old in previous.items():
                if old is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = old

    if not checks.get("owned_database_removed"):
        status = "FAILED"
    sources = {str(path): store.put_bytes(path.read_bytes()) for path in sorted(Path("src/autoseal").glob("*.py"))}
    sources[str(Path(__file__))] = store.put_bytes(Path(__file__).read_bytes())
    report = {"kind": "local_platform_e2e", "schema_version": 1, "status": status, "error": error,
        "started_at_utc": started, "finished_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": time.monotonic() - clock, "steps": steps, "checks": checks,
        "sources": sources, "api_log_id": api_log_id, "managed_report_id": args.managed_id,
        "controls": [{k: row[k] for k in ("id", "candidate", "classification", "manifest_id")} for row in runs],
        "limitations": ["Checked-in synthetic fixtures only; no real model or training.",
            "Lease expiry is an explicit injected database fault, not a killed-worker experiment.",
            "Local unauthenticated API; no public deployment or full V1 acceptance."]}
    identity = store.put_json(report)
    (args.root / "report.json").write_text(json.dumps({"report_id": identity}, indent=2) + "\n")
    print(json.dumps({"report_id": identity, "status": status, "checks": checks, "error": error}, indent=2))
    return 0 if status == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
