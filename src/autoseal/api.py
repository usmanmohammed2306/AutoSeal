"""Local FastAPI surface for persisted AutoSeal runs.

The request process records intent. A separate worker must process runs. This
Authentication is optional for loopback development and mandatory before any
external exposure. Registered repair jobs execute only in the separate worker.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Callable, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import sessionmaker

from autoseal.db import EventRow, RunRow, make_session_factory
from autoseal.service import RunService, docker_compare
from autoseal.storage import ContentAddressedStore
from autoseal.influence import fixture_influence_graph
from autoseal.investigation import minimize_fixture
from autoseal.repair import RepairOperator, RepairPlan, local_repair_search
from autoseal.promotion import review_local_repair
from autoseal.repair_engine import local_composed_policy_preview
from autoseal.upstream_swesmith import compare_missing_tests_case
from autoseal.upstream_swebench import compare_swebench_case, preview_swebench_f2p_repair


class RunCreate(BaseModel):
    candidate: str
    idempotency_key: Optional[str] = Field(default=None, min_length=1, max_length=128)


class ModelRunImport(BaseModel):
    identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class WorkflowCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(max_length=32)
    payload: dict
    idempotency_key: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{1,128}$")


def _workflow_json(row):
    return {key: getattr(row, key) for key in ("id", "kind", "payload", "state", "attempts", "result_id", "error")} | {
        "created_at": row.created_at.isoformat(), "updated_at": row.updated_at.isoformat()}


def _run_json(row: RunRow) -> dict:
    return {
        "id": row.id,
        "candidate": row.candidate,
        "state": row.state,
        "classification": row.classification,
        "manifest_id": row.manifest_id,
        "error": row.error,
        "attempts": row.attempts,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


def _event_json(row: EventRow) -> dict:
    return {
        "id": row.id,
        "run_id": row.run_id,
        "kind": row.kind,
        "payload": row.payload,
        "created_at": row.created_at.isoformat(),
    }


def create_app(
    database_url: str,
    evidence_root: Path,
    *,
    evaluator: Callable[[str], dict] = docker_compare,
    managed_report_root: Optional[Path] = None,
    managed_report_identity: Optional[str] = None,
    workflow_root: Optional[Path] = None,
    operator_token: Optional[str] = None,
    reader_token: Optional[str] = None,
    shell_archive_root: Optional[Path] = None,
    shell_archive_identity: Optional[str] = None,
    sft_archive_root: Optional[Path] = None,
    sft_evaluation_identity: Optional[str] = None,
    study_archive_root: Optional[Path] = None,
    study_evaluation_identity: Optional[str] = None,
) -> FastAPI:
    if (study_archive_root is None) != (study_evaluation_identity is None):
        raise ValueError('study archive root and pinned evaluation must be configured together')
    if (managed_report_root is None) != (managed_report_identity is None):
        raise ValueError("managed report root and pinned identity must be configured together")
    if (shell_archive_root is None) != (shell_archive_identity is None):
        raise ValueError("native shell archive root and pinned identity must be configured together")
    if (sft_archive_root is None) != (sft_evaluation_identity is None):
        raise ValueError("SFT archive root and pinned evaluation must be configured together")
    sessions: sessionmaker = make_session_factory(database_url)
    store = ContentAddressedStore(evidence_root)
    service = RunService(sessions, store, evaluator=evaluator)
    app = FastAPI(title="AutoSeal Lab", version="0.1.0")
    app.state.run_service = service
    from autoseal.access import AccessPolicy
    from autoseal.workflows import WorkflowService, TERMINAL
    from autoseal.artifact_cases import registered_tasks
    workflows = WorkflowService(sessions, store, workflow_root or evidence_root.parent / (evidence_root.name + "-workflows"))
    app.state.workflow_service = workflows
    # Validate configuration at startup, rather than waiting for the first call.
    AccessPolicy(app, operator_token=operator_token, reader_token=reader_token)
    app.add_middleware(AccessPolicy, operator_token=operator_token, reader_token=reader_token)

    @app.get("/api/access")
    def access(request: Request):
        return {"role": request.scope["autoseal.role"], "authentication": bool(operator_token)}

    @app.get("/api/research/sft-calibration")
    def sft_calibration():
        if sft_archive_root is None:
            raise HTTPException(503, "No pinned SFT calibration archive is configured")
        from autoseal.sft_archive import calibration_view
        try:
            return calibration_view(ContentAddressedStore(sft_archive_root / "evidence"), sft_evaluation_identity)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(503, "SFT calibration archive failed verification") from exc

    @app.get('/api/research/model-study')
    def model_study():
        if study_archive_root is None:
            raise HTTPException(503, 'No pinned post-checkpoint model study is configured')
        from autoseal.artifact_study_review import study_review
        try:
            return study_review(study_archive_root, study_evaluation_identity)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            raise HTTPException(503, 'Model study archive failed verification') from exc

    @app.get("/api/research/terminal-shell")
    def native_shell_evidence():
        if shell_archive_root is None:
            raise HTTPException(503, "No pinned native-test shell archive is configured")
        from autoseal.native_shell_archive import verify_shell_report
        try:
            return verify_shell_report(ContentAddressedStore(shell_archive_root / "evidence"), shell_archive_identity)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(503, "native-test shell archive failed verification") from exc

    @app.get("/api/cases")
    def cases():
        return [{"id": key, "task": task.model_dump(mode="json"), "origin": "seeded"}
                for key, task in registered_tasks().items()]

    @app.post("/api/workflows", status_code=202)
    def create_workflow(request: WorkflowCreate):
        try:
            return _workflow_json(workflows.submit(request.kind, request.payload, request.idempotency_key))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            raise HTTPException(400, "invalid workflow or unavailable verified target") from exc

    @app.get("/api/workflows")
    def list_workflows(limit: int = Query(default=50, ge=1, le=100)):
        return [_workflow_json(row) for row in workflows.list(limit)]

    def require_workflow(identity):
        try:
            row = workflows.get(identity)
        except (ValueError, TypeError, AttributeError) as exc:
            raise HTTPException(400, "invalid workflow identity") from exc
        if row is None:
            raise HTTPException(404, "workflow not found")
        return row

    @app.get("/api/workflows/{identity}")
    def get_workflow(identity: str):
        return _workflow_json(require_workflow(identity))

    @app.post("/api/workflows/{identity}/{action}")
    def mutate_workflow(identity: str, action: str):
        require_workflow(identity)
        if action not in {"cancel", "retry"}:
            raise HTTPException(404, "unknown workflow action")
        try:
            return _workflow_json(getattr(workflows, action)(identity))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/workflows/{identity}/events")
    def workflow_events(identity: str, after_id: int = Query(default=0, ge=0)):
        require_workflow(identity)
        return [{"id": row.id, "kind": row.kind, "payload": row.payload,
                 "created_at": row.created_at.isoformat()} for row in workflows.events(identity, after_id)]

    @app.get("/api/workflows/{identity}/result")
    def workflow_result(identity: str):
        row = require_workflow(identity)
        if row.result_id is None:
            raise HTTPException(404, "workflow result unavailable")
        try:
            return workflows.result(identity)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(500, "stored workflow evidence failed verification") from exc

    @app.get("/api/workflows/{identity}/validation")
    def workflow_validation(identity: str):
        row = require_workflow(identity)
        if row.kind != "artifact_validate" or row.state != "COMPLETED":
            raise HTTPException(409, "completed validation required")
        try:
            return workflows.validation(identity)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(500, "stored validation evidence failed verification") from exc

    @app.get("/api/workflows/{identity}/stream")
    async def workflow_stream(identity: str, after_id: int = Query(default=0, ge=0)):
        require_workflow(identity)
        async def events():
            last_id = after_id
            while True:
                for row in workflows.events(identity, last_id):
                    last_id = row.id
                    payload = {"id": row.id, "kind": row.kind, "payload": row.payload}
                    yield f"id: {row.id}\nevent: workflow\ndata: {json.dumps(payload)}\n\n"
                if require_workflow(identity).state in TERMINAL:
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)
        return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "mode": "local-research"}

    @app.post("/api/runs", status_code=202)
    def create_run(request: RunCreate) -> dict:
        try:
            row = service.submit(request.candidate, request.idempotency_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return _run_json(row)

    @app.get("/api/runs")
    def list_runs(limit: int = Query(default=50, ge=1, le=100)) -> list[dict]:
        return [_run_json(row) for row in service.list_runs(limit)]

    @app.post("/api/model-runs/import", status_code=201)
    def import_model_run(request: ModelRunImport) -> dict:
        try:
            return _run_json(service.import_model_run(request.identity))
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="model evidence missing or invalid") from exc

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict:
        row = service.get(run_id)
        if row is None:
            raise HTTPException(status_code=404, detail="run not found")
        return _run_json(row)

    @app.get("/api/runs/{run_id}/events")
    def get_events(run_id: str, after_id: int = Query(default=0, ge=0)) -> list[dict]:
        if service.get(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")
        return [_event_json(row) for row in service.events(run_id, after_id)]

    @app.get("/api/runs/{run_id}/evidence")
    def get_evidence(run_id: str) -> dict:
        row = service.get(run_id)
        if row is None or row.manifest_id is None:
            raise HTTPException(status_code=404, detail="evidence not available")
        try:
            return store.get_json(row.manifest_id)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=500, detail="stored evidence failed verification") from exc

    @app.get("/api/runs/{run_id}/stream")
    async def stream_events(run_id: str, after_id: int = Query(default=0, ge=0)) -> StreamingResponse:
        if service.get(run_id) is None:
            raise HTTPException(status_code=404, detail="run not found")

        async def events():
            last_id = after_id
            while True:
                for event in service.events(run_id, last_id):
                    last_id = event.id
                    yield f"id: {event.id}\nevent: {event.kind.lower()}\ndata: {json.dumps(_event_json(event))}\n\n"
                row = service.get(run_id)
                if row is None or row.state in {"COMPLETED", "FAILED"}:
                    break
                await asyncio.sleep(0.5)

        return StreamingResponse(events(), media_type="text/event-stream")

    @app.get("/api/research/fixtures/{candidate}/influence")
    def fixture_influence(candidate: str) -> dict:
        try:
            graph = fixture_influence_graph(candidate)
            witness = minimize_fixture(candidate)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "graph": graph.model_dump(mode="json"),
            "witness": witness.model_dump(mode="json"),
            "scope": "checked-in benign fixture; file-level intervention",
        }

    @app.get("/api/research/repair-preview")
    def repair_preview() -> dict:
        return {
            "plans": [item.model_dump(mode="json") for item in local_repair_search()],
            "scope": "local fixture preview, not a promoted V1 repair",
        }

    @app.get("/api/research/managed-repair")
    def retained_managed_repair() -> dict:
        if managed_report_root is None:
            raise HTTPException(status_code=503, detail="No pinned managed-validation archive is configured")
        from autoseal.managed_review import managed_review
        try:
            return managed_review(managed_report_root, managed_report_identity)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(status_code=503, detail="Managed-validation archive failed integrity checks") from exc

    @app.get("/api/research/promotion-review")
    def promotion_review() -> dict:
        plan = RepairPlan(
            operator=RepairOperator.ARTIFACT_PROJECTION,
            allowed_files=("solution.py",),
        )
        return review_local_repair(plan).model_dump(mode="json")

    @app.get("/api/research/repair-plan-preview")
    def repair_plan_preview() -> dict:
        return local_composed_policy_preview()

    @app.get("/api/research/upstream-swesmith")
    def upstream_swesmith() -> dict:
        return {
            "cases": [
                compare_missing_tests_case(name).model_dump(mode="json")
                for name in ("collection_failure", "legitimate_solution", "ordinary_failure")
            ],
            "scope": "historical upstream grader regression, not a current benchmark exploit",
        }

    @app.get("/api/research/upstream-swebench")
    def upstream_swebench() -> dict:
        return {
            "cases": [
                compare_swebench_case(name).model_dump(mode="json")
                for name in ("xfail", "skip", "clean", "positive")
            ],
            "scope": "local reproduction with pinned current grader and parser, not a native Verified instance run",
        }

    @app.get("/api/research/native-swebench")
    def native_swebench_evidence() -> dict:
        from autoseal.native_swebench import load_native_case
        from autoseal.native_swebench_audit import load_native_audit
        root = Path(__file__).resolve().parents[2] / "examples/upstream_swebench/native"
        try:
            index = json.loads((root / "index.json").read_text())
            audit_index = json.loads((root / "audit_index.json").read_text())
            archived = ContentAddressedStore(root / "evidence")
            audits = {item["case"]: (item["identity"], load_native_audit(archived, item["identity"]))
                      for item in audit_index["controls"]}
            controls = []
            for item in index["controls"]:
                audit_id, audit = audits[item["case"]]
                if audit.native_receipt_id != item["identity"]:
                    raise ValueError("native/audit case linkage mismatch")
                controls.append({"identity": item["identity"], "role": item["role"],
                                 "audit_identity": audit_id, "audit_verdict": audit.verdict,
                                 "audit_checks": audit.checks,
                                 **load_native_case(archived, item["identity"]).model_dump(mode="json")})
            return {"instance_id": index["instance_id"], "controls": controls,
                    "disclosure": index["disclosure"], "limitation": index["limitation"],
                    "audit_limitation": audit_index["limitation"]}
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="native archive missing or failed integrity checks") from exc

    @app.get("/api/research/native-swebench/objects/{digest}")
    def native_swebench_object(digest: str) -> dict:
        import re
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HTTPException(status_code=400, detail="invalid evidence identity")
        root = Path(__file__).resolve().parents[2] / "examples/upstream_swebench/native/evidence"
        try:
            content = ContentAddressedStore(root).get_bytes("sha256:" + digest)
            if len(content) > 2 * 1024 * 1024:
                raise ValueError("object exceeds preview limit")
            return {"identity": "sha256:" + digest, "content": content.decode("utf-8")}
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="evidence missing or failed verification") from exc

    @app.get("/api/research/upstream-swebench/repair-preview")
    def upstream_swebench_repair_preview() -> dict:
        return preview_swebench_f2p_repair().model_dump(mode="json")

    @app.get("/api/research/training-pilots")
    def training_pilots() -> dict:
        from collections import Counter
        from autoseal.training_pilot_archive import load_training_pilot_archive, load_training_preflight_archive
        root = Path(__file__).resolve().parents[2] / "examples/training_pilot"
        try:
            pilots = [{"id": name, **load_training_pilot_archive(root / name)}
                      for name in ("grpo_bridge_d", "grpo_bridge_e", "grpo_bridge_f", "grpo_bridge_i_paired")
                      if (root / name / "index.json").is_file()]
            preflights = []
            for name in ("grpo_bridge_g", "grpo_bridge_h", "grpo_bridge_i"):
                if not (root / name / "index.json").is_file():
                    continue
                index = load_training_preflight_archive(root / name)
                store = ContentAddressedStore(root / name)
                report = store.get_json(index["report_id"])
                responses = [store.get_json(pair["response_id"]) for pair in index["observed"]]
                outcomes = Counter(outcome for response in responses for outcome in response["outcomes"])
                preflights.append({"id": name, **index, "report_status": report["status"],
                                   "global_steps": report["global_steps"], "outcomes": dict(sorted(outcomes.items())),
                                   "reward_sum": sum(value for response in responses
                                                     for value in response["rewards"] if value is not None),
                                   "samples": sum(len(response["rewards"]) for response in responses),
                                   "evaluator_failures": sum(response["status"] != "COMPLETE" for response in responses),
                                   "max_gradient_norm": max((float(row["grad_norm"]) for row in report.get("log_history", [])
                                                             if "grad_norm" in row), default=0.0)})
            return {"pilots": pilots, "preflights": preflights,
                    "scope": "Verified smoke evidence only, not the frozen research study"}
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(status_code=503, detail="training pilot archive failed integrity checks") from exc

    @app.get("/api/research/training-pilots/{pilot}/objects/{digest}")
    def training_pilot_object(pilot: str, digest: str) -> dict:
        import re
        if pilot not in {"grpo_bridge_d", "grpo_bridge_e", "grpo_bridge_f", "grpo_bridge_i_paired", "grpo_bridge_g", "grpo_bridge_h", "grpo_bridge_i"} or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HTTPException(status_code=400, detail="invalid pilot or content identity")
        root = Path(__file__).resolve().parents[2] / "examples/training_pilot" / pilot
        try:
            content = ContentAddressedStore(root).get_bytes("sha256:" + digest)
            if len(content) > 2 * 1024 * 1024:
                raise ValueError("object exceeds preview limit")
            return {"identity": "sha256:" + digest, "content": content.decode("utf-8")}
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="pilot evidence missing or failed verification") from exc

    return app
