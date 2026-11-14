"""Durable registered repair workflows, fencing, cancellation and recovery."""

from __future__ import annotations

from datetime import timedelta
import json
from pathlib import Path
import re
import uuid

from sqlalchemy import and_, or_, select
from sqlalchemy.exc import IntegrityError as DatabaseIntegrityError

from autoseal.artifact_cases import load_case, registered_tasks
from autoseal.artifact_pipeline import (deployment_manager, evaluate_artifact, promote_artifact,
    resolve_artifact, rollback_artifact, validate_artifact_case, verify_artifact_validation)
from autoseal.artifact_runtime import execution_scope
from autoseal.db import WorkflowEventRow, WorkflowRow, utc_now
from autoseal.execution import run_command
from autoseal.storage import ContentAddressedStore, IntegrityError


KINDS = {"artifact_validate", "artifact_promote", "artifact_rollback", "artifact_replay"}
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}


class WorkflowCancelled(RuntimeError):
    pass


def _uuid(value):
    if str(uuid.UUID(value)) != value:
        raise ValueError("workflow identity is not a canonical UUID")
    return value


def cleanup_scope(store, scope):
    listed = run_command(["docker", "ps", "--all", "--quiet", "--filter", "label=autoseal.scope=" + scope], timeout_seconds=10)
    if listed.exit_code != 0 or listed.stdout_truncated:
        raise RuntimeError("cannot enumerate previous workflow containers")
    ids = listed.stdout.split()
    if len(ids) > 32 or any(not re.fullmatch(r"[0-9a-f]{12,64}", item) for item in ids):
        raise IntegrityError("unexpected workflow container inventory")
    receipts = [store.put_json(listed.to_dict())]
    for container in ids:
        inspected = run_command(["docker", "inspect", container], timeout_seconds=10)
        if inspected.exit_code != 0 or inspected.stdout_truncated:
            raise RuntimeError("cannot verify previous workflow container ownership")
        body = json.loads(inspected.stdout)
        if len(body) != 1 or body[0]["Config"].get("Labels", {}).get("autoseal.scope") != scope:
            raise IntegrityError("refusing to remove a container from another workflow")
        removed = run_command(["docker", "rm", "-f", container], timeout_seconds=10)
        receipts.extend([store.put_json(inspected.to_dict()), store.put_json(removed.to_dict())])
        if removed.exit_code != 0:
            raise RuntimeError("workflow container cleanup failed")
    return store.put_json({"kind": "workflow_container_recovery", "scope": scope,
        "removed_containers": ids, "process_receipts": receipts})


class WorkflowService:
    def __init__(self, sessions, store: ContentAddressedStore, root: Path):
        self.sessions, self.store, self.root = sessions, store, root
        if root.is_symlink():
            raise ValueError("workflow root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True)

    def get(self, identity):
        _uuid(identity)
        with self.sessions() as session:
            return session.get(WorkflowRow, identity)

    def list(self, limit=50):
        with self.sessions() as session:
            return list(session.scalars(select(WorkflowRow).order_by(WorkflowRow.created_at.desc()).limit(limit)))

    def events(self, identity, after=0):
        _uuid(identity)
        with self.sessions() as session:
            return list(session.scalars(select(WorkflowEventRow).where(
                WorkflowEventRow.workflow_id == identity, WorkflowEventRow.id > after).order_by(WorkflowEventRow.id)))

    def _event(self, session, row, kind, payload=None):
        session.add(WorkflowEventRow(workflow_id=row.id, kind=kind, payload=payload or {}))

    def submit(self, kind, payload, key):
        if kind not in KINDS or not isinstance(payload, dict) or not isinstance(key, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", key):
            raise ValueError("invalid registered workflow request")
        if kind == "artifact_validate":
            if set(payload) != {"case"} or payload["case"] not in registered_tasks():
                raise ValueError("unknown registered artifact case")
        else:
            allowed = {"validation_job_id", "candidate"} if kind == "artifact_replay" else {"validation_job_id"}
            if set(payload) != allowed:
                raise ValueError("invalid workflow payload")
            _uuid(payload["validation_job_id"])
            self._target(payload["validation_job_id"])
            if kind == "artifact_replay" and payload["candidate"] not in {
                    "valid_reduce", "valid_loop", "invalid_zero", "invalid_other", "exploit", "development", "heldout_a", "heldout_b"}:
                raise ValueError("unknown frozen replay control")
        with self.sessions() as session:
            existing = session.scalar(select(WorkflowRow).where(WorkflowRow.kind == kind, WorkflowRow.idempotency_key == key))
            if existing:
                if existing.payload != payload:
                    raise ValueError("idempotency key belongs to another payload")
                return existing
            row = WorkflowRow(id=str(uuid.uuid4()), kind=kind, payload=payload, idempotency_key=key,
                              state="QUEUED", attempts=0)
            try:
                session.add(row)
                # These mappers intentionally have no ORM relationship. Flush
                # the parent before its FK event, within the same transaction.
                session.flush()
                self._event(session, row, "QUEUED", {"kind": kind})
                session.commit()
            except DatabaseIntegrityError:
                session.rollback()
                existing = session.scalar(select(WorkflowRow).where(WorkflowRow.kind == kind, WorkflowRow.idempotency_key == key))
                if existing is None or existing.payload != payload:
                    raise ValueError("idempotency conflict")
                return existing
            return row

    def cancel(self, identity):
        with self.sessions() as session:
            row = session.get(WorkflowRow, _uuid(identity), with_for_update=True)
            if row is None:
                raise ValueError("workflow not found")
            if row.state in TERMINAL:
                return row
            if row.state == "QUEUED":
                row.state = "CANCELLED"
            elif row.kind in {"artifact_promote", "artifact_rollback"}:
                raise ValueError("an executing atomic revision mutation cannot be cancelled")
            else:
                row.state = "CANCEL_REQUESTED"
            self._event(session, row, row.state)
            session.commit()
            return row

    def retry(self, identity):
        with self.sessions() as session:
            row = session.get(WorkflowRow, _uuid(identity), with_for_update=True)
            if row is None or row.state != "FAILED" or row.attempts >= 3:
                raise ValueError("workflow is not retryable")
            row.state, row.error = "QUEUED", None
            self._event(session, row, "RETRY_REQUESTED")
            session.commit()
            return row

    def _heartbeat(self, identity, token, stage=None, payload=None, *, allow_cancel=False):
        with self.sessions() as session:
            row = session.get(WorkflowRow, identity, with_for_update=True)
            if row is None or row.lease_token != token or row.state not in {"RUNNING", "CANCEL_REQUESTED"}:
                raise RuntimeError("workflow lease was lost")
            if row.state == "CANCEL_REQUESTED" and not allow_cancel:
                raise WorkflowCancelled("workflow cancellation requested")
            row.lease_expires_at = utc_now() + timedelta(seconds=120)
            if stage:
                self._event(session, row, stage, payload)
            session.commit()

    def _target(self, identity):
        row = self.get(identity)
        if row is None or row.kind != "artifact_validate" or row.state != "COMPLETED" or row.result_id is None:
            raise ValueError("target must be a completed artifact validation workflow")
        result = self.store.get_json(row.result_id)
        if type(result.get("attempt")) is not int or not 1 <= result["attempt"] <= 3:
            raise IntegrityError("invalid validation attempt")
        root = self.root / row.id / str(result["attempt"])
        if root.is_symlink() or root.parent.is_symlink() or not root.is_relative_to(self.root):
            raise IntegrityError("unsafe workflow archive path")
        store = ContentAddressedStore(root / "evidence")
        report = verify_artifact_validation(store, result["validation_id"])
        return root, store, result["validation_id"], report

    def result(self, identity):
        row = self.get(identity)
        if row is None or row.result_id is None:
            raise ValueError("workflow result not available")
        return self.store.get_json(row.result_id)

    def validation(self, identity):
        root, store, validation_id, report = self._target(identity)
        case, task = load_case(store, report["case_id"])
        search = store.get_json(report["search_id"])
        def outcome(ref):
            receipt = store.get_json(ref)
            return self._evaluation_payload(store, receipt)
        controls = [{"name": control["name"], "role": control["role"],
            "proxy": outcome(baseline["proxy"])["verdict"], "audit": outcome(baseline["audit"])["verdict"],
            "sealed": [outcome(ref)["verdict"] for ref in row["sealed"]]}
            for control, baseline, row in zip(case["controls"], report["baseline"], report["controls"])]
        return {"validation_id": validation_id, "task": task.model_dump(mode="json"), "gates": report["gates"],
            "controls": controls, "search": search, "graph": store.get_json(report["graph_id"]),
            "parent_revision": report["parent_revision"], "child_revision": report["child_revision"],
            "witness_id": report["witness_id"], "rollback_id": report["rollback_id"],
            "limitations": ["Seeded fixed-output task; not an external benchmark result.",
                            "Finite preservation and committed variants, not universal exploit exclusion."]}

    @staticmethod
    def _evaluation_payload(store, receipt):
        from autoseal.result_binding import ResultContext, resolve_result
        return resolve_result(store, store.put_json(receipt), ResultContext.model_validate(receipt["context"]), channel=receipt["channel"])

    def process_one(self):
        with self.sessions() as session:
            row = session.scalar(select(WorkflowRow).where(or_(WorkflowRow.state == "QUEUED", and_(
                WorkflowRow.state.in_(["RUNNING", "CANCEL_REQUESTED"]), WorkflowRow.lease_expires_at < utc_now())))
                .order_by(WorkflowRow.created_at).with_for_update(skip_locked=True).limit(1))
            if row is None:
                return None
            cancelled = row.state == "CANCEL_REQUESTED"
            old_attempts = row.attempts
            row.attempts += 1
            row.state = "CANCEL_REQUESTED" if cancelled else "RUNNING"
            row.lease_token = str(uuid.uuid4())
            row.lease_expires_at = utc_now() + timedelta(seconds=120)
            identity, token, attempt, kind, payload = row.id, row.lease_token, row.attempts, row.kind, row.payload
            self._event(session, row, "CLAIMED", {"attempt": attempt, "reclaimed": old_attempts > 0})
            session.commit()
        result_id, error, state = None, None, "FAILED"
        try:
            for old in range(1, old_attempts + 1):
                recovery_id = cleanup_scope(self.store, f"{identity}.{old}")
                self._heartbeat(identity, token, "PREVIOUS_ATTEMPT_CLEANED", {"evidence_id": recovery_id}, allow_cancel=True)
            if cancelled:
                raise WorkflowCancelled("cancelled worker was recovered")
            if attempt > 3:
                raise RuntimeError("workflow retry budget exhausted")
            self._heartbeat(identity, token)
            with execution_scope(f"{identity}.{attempt}", lambda: self._heartbeat(identity, token)):
                if kind == "artifact_validate":
                    target = self.root / identity / str(attempt)
                    validation_id = validate_artifact_case(target, registered_tasks()[payload["case"]],
                        progress=lambda stage, value: self._heartbeat(identity, token, stage, value))
                    result = {"kind": kind, "validation_id": validation_id, "attempt": attempt}
                else:
                    target, store, validation_id, report = self._target(payload["validation_job_id"])
                    if kind == "artifact_promote":
                        result = promote_artifact(target, validation_id)
                    elif kind == "artifact_rollback":
                        manager = deployment_manager(target)
                        if manager.active() == report["parent_revision"]:
                            pointer = json.loads((manager.root / "active.json").read_bytes())
                            transition = store.get_json(pointer["transition"])
                            if transition["action"] != "rollback" or transition["before"] != report["child_revision"]:
                                raise IntegrityError("parent was not restored by this child's rollback")
                            rollback_id = pointer["transition"]
                        else:
                            rollback_id = rollback_artifact(target, report["child_revision"])
                        result = {"rollback_id": rollback_id, "restored_revision": report["parent_revision"]}
                    else:
                        case, _ = load_case(store, report["case_id"])
                        control = next(c for c in case["controls"] if c["name"] == payload["candidate"])
                        revision = deployment_manager(target).active()
                        channel = "sealed" if revision == report["child_revision"] else "proxy"
                        ref = evaluate_artifact(store, report["case_id"], control["candidate_id"], revision, channel)
                        checked = resolve_artifact(store, ref, case_id=report["case_id"], candidate_id=control["candidate_id"], revision_id=revision, channel=channel)
                        result = {"evaluation_id": ref, "verdict": checked["verdict"], "revision": revision,
                                  "replay_kind": "fresh artifact execution, not stochastic inference reproduction"}
                    result.update(kind=kind, validation_job_id=payload["validation_job_id"])
                self._heartbeat(identity, token)
                result_id = self.store.put_json(result)
                state = "COMPLETED"
        except WorkflowCancelled as exc:
            state, error = "CANCELLED", str(exc)
        except (OSError, RuntimeError, ValueError, KeyError, StopIteration) as exc:
            error = str(exc)[:500]
        finally:
            try:
                cleanup_id = cleanup_scope(self.store, f"{identity}.{attempt}")
            except (OSError, RuntimeError, ValueError) as exc:
                state, error, cleanup_id = "FAILED", "workflow cleanup failed: " + str(exc)[:400], None
        with self.sessions() as session:
            row = session.get(WorkflowRow, identity, with_for_update=True)
            if row.lease_token != token:
                raise RuntimeError("workflow lease lost before result commit")
            if row.state == "CANCEL_REQUESTED" and state == "COMPLETED":
                state, error = "CANCELLED", "cancelled before publishing validation result"
            row.state, row.result_id, row.error = state, result_id, error
            row.lease_token = row.lease_expires_at = None
            self._event(session, row, state, {"result_id": result_id, "cleanup_id": cleanup_id, "error": error})
            session.commit()
            return row
