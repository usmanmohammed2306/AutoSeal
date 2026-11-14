"""Content-bound, bounded execution of registered artifact-task workers.

Only byte bundles prepared by the trusted case adapter enter this interface.
It is not exposed as an arbitrary Docker-command or filesystem HTTP API.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import re
import tempfile
import uuid

from autoseal.docker_profile import readonly_python_command
from autoseal.evidence import CommandEvidence
from autoseal.execution import run_command
from autoseal.owned_verifier import inspect_enforcement
from autoseal.projection import safe_relative_artifact_path
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


_SCOPE = ContextVar("artifact_execution_scope", default=(None, None))


@contextmanager
def execution_scope(scope, before_execution):
    if not re.fullmatch(r"[0-9a-f-]{36}\.[1-9][0-9]{0,2}", scope):
        raise ValueError("invalid workflow execution scope")
    token = _SCOPE.set((scope, before_execution))
    try:
        yield
    finally:
        _SCOPE.reset(token)


def freeze_files(store: ContentAddressedStore, files: dict[str, bytes]) -> str:
    if not files or len(files) > 32 or any(not safe_relative_artifact_path(name) for name in files):
        raise ValueError("artifact bundle requires 1 to 32 canonical paths")
    if sum(map(len, files.values())) > 4 * 1024 * 1024 or any(len(data) > 1024 * 1024 for data in files.values()):
        raise ValueError("artifact bundle exceeds its byte budget")
    return store.put_json({"kind": "artifact_input_bundle", "schema_version": 1,
                           "files": {name: store.put_bytes(data) for name, data in sorted(files.items())}})


def load_files(store: ContentAddressedStore, identity: str) -> dict[str, bytes]:
    body = store.get_json(identity)
    if body["kind"] != "artifact_input_bundle" or body["schema_version"] != 1:
        raise IntegrityError("unsupported artifact input bundle")
    files = {name: store.get_bytes(ref) for name, ref in body["files"].items()}
    if freeze_files(store, files) != identity:
        raise IntegrityError("noncanonical artifact bundle")
    return files


def _succeeded(raw: dict) -> bool:
    CommandEvidence.model_validate(raw)
    return raw["status"] == "exited_zero" and not raw["stdout_truncated"] and not raw["stderr_truncated"]


def execute_bundle(store: ContentAddressedStore, bundle_id: str, *, image: str, worker: str, payload) -> str:
    files = load_files(store, bundle_id)
    name = "autoseal-artifact-" + uuid.uuid4().hex
    scope, before = _SCOPE.get()
    with tempfile.TemporaryDirectory(prefix="autoseal-artifact-") as temporary:
        root = Path(temporary) / "input"
        root.mkdir()
        for relative, data in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        if before:
            before()
        created = run_command(readonly_python_command(name, root, image, worker, payload, scope=scope),
                              timeout_seconds=15, max_output_bytes=4096)
        if not _succeeded(created.to_dict()):
            raise RuntimeError("artifact container creation failed")
        try:
            if before:
                before()
            inspected = run_command(["docker", "inspect", name], timeout_seconds=10, max_output_bytes=64 * 1024)
            if not _succeeded(inspected.to_dict()):
                raise IntegrityError("artifact container inspection failed")
            body = json.loads(inspected.stdout)
            if not isinstance(body, list) or len(body) != 1:
                raise IntegrityError("unexpected artifact container inspection")
            gates = inspect_enforcement(body[0], image=image, candidate_root=root)
            if not all(gates.values()):
                raise IntegrityError("artifact container violates the read-only profile")
            process = run_command(["docker", "start", "--attach", name], timeout_seconds=15,
                                  max_output_bytes=32 * 1024)
        finally:
            removed = run_command(["docker", "rm", "-f", name], timeout_seconds=10, max_output_bytes=4096)
            if not _succeeded(removed.to_dict()):
                raise RuntimeError("artifact container cleanup failed")
        if {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()} != files:
            raise IntegrityError("read-only input bundle changed")
    return store.put_json({"schema_version": 1, "kind": "artifact_runtime_receipt", "bundle_id": bundle_id,
        "worker_id": store.put_bytes(worker.encode()), "payload_id": store.put_json(payload), "image": image,
        "creation_id": store.put_json(created.to_dict()), "inspection_id": store.put_json(inspected.to_dict()),
        "process_id": store.put_json(process.to_dict()), "cleanup_id": store.put_json(removed.to_dict()),
        "enforcement": gates, "scope": scope})


def verify_bundle_execution(store: ContentAddressedStore, identity: str, *, bundle_id: str,
                            image: str, worker: str, payload) -> dict:
    result = store.get_json(identity)
    if (result["kind"] != "artifact_runtime_receipt" or result["schema_version"] != 1
            or result["bundle_id"] != bundle_id or result["image"] != image
            or store.get_bytes(result["worker_id"]) != worker.encode()
            or store.get_json(result["payload_id"]) != payload):
        raise IntegrityError("artifact execution belongs to different inputs or worker")
    load_files(store, bundle_id)
    created, inspected, process, cleaned = [store.get_json(result[key]) for key in
        ("creation_id", "inspection_id", "process_id", "cleanup_id")]
    if not all(_succeeded(raw) for raw in (created, inspected, cleaned)):
        raise IntegrityError("artifact lifecycle receipt is incomplete")
    CommandEvidence.model_validate(process)
    body = json.loads(inspected["stdout"])
    if not isinstance(body, list) or len(body) != 1:
        raise IntegrityError("artifact inspection is not one container")
    body = body[0]
    name = body["Name"].removeprefix("/")
    mounts = body.get("Mounts", [])
    if len(mounts) != 1:
        raise IntegrityError("artifact container has extra mounts")
    root = Path(mounts[0]["Source"])
    if (created["command"] != readonly_python_command(name, root, image, worker, payload, scope=result.get("scope"))
            or created["stdout"].strip() != body["Id"]
            or inspected["command"] != ["docker", "inspect", name]
            or process["command"] != ["docker", "start", "--attach", name]
            or cleaned["command"] != ["docker", "rm", "-f", name]
            or cleaned["stdout"].strip() not in {name, body["Id"]}
            or body["Config"].get("Cmd") != ["-I", "-c", worker, json.dumps(payload)]
            or body["Config"].get("Entrypoint") != ["python"]):
        raise IntegrityError("artifact lifecycle linkage differs from the selected execution")
    if result.get("scope") and body["Config"].get("Labels", {}).get("autoseal.scope") != result["scope"]:
        raise IntegrityError("artifact container belongs to another workflow scope")
    gates = inspect_enforcement(body, image=image, candidate_root=root)
    if gates != result["enforcement"] or not all(gates.values()):
        raise IntegrityError("artifact enforcement evidence disagrees")
    return {"process": process, "inspection": body, "enforcement": gates}
