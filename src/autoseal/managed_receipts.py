"""Recompute scoped validation facts from retained bytes, without Docker.

The trusted input is the caller-selected report digest and manager-owned CAS.
Hashes are content binding, not signatures or proof against a dishonest host.
Nothing in this module imports or executes stored candidate or driver code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from autoseal.evidence import CommandEvidence
from autoseal.local_demo import _counts, candidate_identity
from autoseal.owned_verifier import AUDIT_INPUTS, INPUTS, WORKER, inspect_enforcement, interpret_answers
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


def snapshot_candidate(store: ContentAddressedStore, path: Path) -> dict:
    """Retain every declared input, including post-selection hook bytes."""

    before = candidate_identity(path)
    files = {p.relative_to(path).as_posix(): store.put_bytes(p.read_bytes())
             for p in sorted(path.rglob("*")) if p.is_file()}
    snapshot = {"candidate_identity": before, "files": files}
    load_candidate_snapshot(store, snapshot)
    if candidate_identity(path) != before:
        raise IntegrityError("candidate changed while snapshotting")
    return snapshot


def load_candidate_snapshot(store: ContentAddressedStore, snapshot: dict) -> dict[str, bytes]:
    files = snapshot["files"]
    if "solution.py" not in files or not set(files) <= {"solution.py", "conftest.py"}:
        raise IntegrityError("unsupported candidate snapshot contract")
    content = {name: store.get_bytes(ref) for name, ref in files.items()}
    manifest = [{"path": name, "sha256": hashlib.sha256(content[name]).hexdigest()}
                for name in sorted(content)]
    identity = "sha256:" + hashlib.sha256(
        b"autoseal.candidate.v1\0" + canonical_json(manifest)).hexdigest()
    if identity != snapshot["candidate_identity"]:
        raise IntegrityError("candidate snapshot does not match its frozen identity")
    return content


def _command(store: ContentAddressedStore, identity: str) -> dict:
    raw = store.get_json(identity)
    CommandEvidence.model_validate(raw)
    return raw


def _successful(process: dict) -> bool:
    return (process["status"] == "exited_zero" and not process["stdout_truncated"]
            and not process["stderr_truncated"])


def verify_transport(store: ContentAddressedStore, result: dict, snapshot: dict, *, image: str) -> tuple[dict, dict]:
    """Verify lifecycle, source and container linkage without executing code."""

    load_candidate_snapshot(store, snapshot)
    if (result["candidate_identity"] != snapshot["candidate_identity"]
            or result["image_identity"] != image or result["source_identity"] != snapshot["files"]["solution.py"]):
        raise IntegrityError("runtime result differs from the frozen candidate or image")
    process = _command(store, result["process_id"])
    if canonical_json(process) != canonical_json(result["process"]):
        raise IntegrityError("runtime process differs from retained evidence")
    created = _command(store, result["creation_id"])
    inspected = _command(store, result["inspection_id"])
    cleaned = _command(store, result["cleanup_id"])
    if not all(_successful(p) for p in (created, inspected, cleaned)):
        raise IntegrityError("incomplete Docker lifecycle evidence")
    body = json.loads(inspected["stdout"])
    if not isinstance(body, list) or len(body) != 1 or body[0] != result["container_inspection"]:
        raise IntegrityError("inspection summary differs from daemon output")
    body = body[0]
    name = body["Name"].removeprefix("/")
    create_args = created["command"]
    if (create_args[:2] != ["docker", "create"] or "--name" not in create_args
            or create_args[create_args.index("--name") + 1] != name
            or created["stdout"].strip() != body["Id"]
            or inspected["command"] != ["docker", "inspect", name]
            or process["command"] != ["docker", "start", "--attach", name]
            or cleaned["command"] != ["docker", "rm", "-f", name]
            or cleaned["stdout"].strip() not in {name, body["Id"]}
            or body["Image"] != image):
        raise IntegrityError("Docker receipts refer to different containers or commands")
    mounts = body.get("Mounts", [])
    if len(mounts) != 1:
        raise IntegrityError("unexpected runtime mounts")
    mount = mounts[0]
    mount_arg = f"type=bind,src={mount['Source']},dst={mount['Destination']},readonly"
    if ("--mount" not in create_args or create_args[create_args.index("--mount") + 1] != mount_arg
            or mount.get("Type") != "bind" or mount.get("RW") is not False):
        raise IntegrityError("mount does not match the retained create command")
    return process, body


def verify_owned_transport(store: ContentAddressedStore, result: dict, snapshot: dict,
                            *, image: str, worker: str, payload) -> dict:
    process, body = verify_transport(store, result, snapshot, image=image)
    config = body["Config"]
    if (store.get_bytes(result["worker_identity"]) != worker.encode()
            or store.get_json(result["inputs_identity"]) != payload
            or config.get("Entrypoint") != ["python"]
            or config.get("Cmd") != ["-I", "-c", worker, json.dumps(payload)]
            or result["projected_files"] != ["solution.py"] or result["owner"] != "trusted_manager"):
        raise IntegrityError("owned worker or behavioral inputs changed")
    gates = inspect_enforcement(body, image=image, candidate_root=Path(body["Mounts"][0]["Source"]))
    if result["enforcement"] != gates or not all(gates.values()):
        raise IntegrityError("enforcement summary differs from daemon evidence")
    return process


def verify_runtime_result(store: ContentAddressedStore, result: dict, snapshot: dict,
                          *, image: str, channel: str) -> dict:
    """Derive verdicts from raw output; inspections alone are not probes."""

    if result["channel"] != channel:
        raise IntegrityError("runtime channel changed")
    if channel in {"audit", "sealed"}:
        inputs = AUDIT_INPUTS if channel == "audit" else INPUTS
        process = verify_owned_transport(store, result, snapshot, image=image, worker=WORKER, payload=list(inputs))
        observed = interpret_answers(process, inputs, audit=channel == "audit")
    elif channel == "proxy":
        process, body = verify_transport(store, result, snapshot, image=image)
        config, mount = body["Config"], body["Mounts"][0]
        expected_files = sorted([*snapshot["files"], "tests/test_solution.py"])
        if (mount.get("Destination") != "/workspace" or sorted(result["copied_files"]) != expected_files
                or config.get("Entrypoint") != ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]):
            raise IntegrityError("baseline verifier contract changed")
        counts = _counts(process["stdout"])
        if process["status"] == "exited_zero":
            verdict = "PASS"
        elif process["status"] == "exited_nonzero" and counts["failed"] > 0:
            verdict = "REJECT"
        else:
            raise IntegrityError("baseline did not produce a decisive verdict")
        observed = {"counts": counts, "verdict": verdict}
    else:
        raise IntegrityError("unknown runtime result channel")
    if any(result[key] != observed[key] for key in ("counts", "verdict")):
        raise IntegrityError("verdict or counts contradict raw process output")
    return observed
