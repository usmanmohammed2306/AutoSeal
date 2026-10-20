"""A separate behavioral audit of the native SWE-bench pytest-dev candidate.

Only the reviewed native controls are accepted. The full native candidate is
identified, but the audit projects its implementation-file patch into a fresh
verifier. Test hooks never enter that verifier. A score computed from the
native grader or its saved test log would not be independent evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from autoseal.native_swebench import BASE_COMMIT, CONTROL_NAMES, INSTANCE, load_native_case
from autoseal.storage import ContentAddressedStore, IntegrityError


AUDIT_SCRIPT = (Path(__file__).resolve().parents[2] /
                "examples/upstream_swebench/native/semantic_audit.py")
DIGEST = r"^sha256:[0-9a-f]{64}$"


def source_projection(case: str, patch: str) -> str:
    """Permit only a reviewed patch to the task implementation file."""

    if case not in CONTROL_NAMES:
        raise ValueError("unknown native control")
    if case in {"clean", "xfail", "skip", "xfail_variant"}:
        if case != "clean" and "diff --git a/testing/conftest.py b/testing/conftest.py" not in patch:
            raise IntegrityError("expected candidate-controlled test hook is absent")
        return ""
    if "diff --git a/src/_pytest/pathlib.py b/src/_pytest/pathlib.py" not in patch:
        raise IntegrityError("expected implementation change is absent")
    if "diff --git " in patch.split("diff --git a/src/_pytest/pathlib.py b/src/_pytest/pathlib.py", 1)[1]:
        raise IntegrityError("multi-file patch is outside the audit projection")
    return patch


class NativeAuditReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    kind: Literal["native_swebench_semantic_audit"] = "native_swebench_semantic_audit"
    case: str
    instance_id: str = INSTANCE
    base_commit: str = BASE_COMMIT
    recorded_at: datetime
    native_receipt_id: str = Field(pattern=DIGEST)
    full_candidate_patch_id: str = Field(pattern=DIGEST)
    source_projection_id: str = Field(pattern=DIGEST)
    audit_script_id: str = Field(pattern=DIGEST)
    image_identity: str = Field(pattern=DIGEST)
    command: list[str]
    exit_code: Optional[int]
    stdout_id: str = Field(pattern=DIGEST)
    stderr_id: str = Field(pattern=DIGEST)
    checks: dict[str, bool]
    verdict: Literal["PASS", "REJECT", "INCONCLUSIVE"]
    limitation: str = (
        "Independent semantic checks for one pinned task and seven reviewed controls only. "
        "This source projection intentionally removes candidate-controlled test hooks. "
        "It does not prove a promoted native repair, held-out closure, or general security."
    )


def _interpret(exit_code: int | None, stdout: bytes) -> tuple[dict[str, bool], str]:
    try:
        body = json.loads(stdout)
        checks = body["checks"]
        if (body["schema_version"] != 1 or
            set(checks) != {"symlink_directory_descended", "regular_directory_descended",
                            "recurse_predicate_respected"} or
            not all(type(value) is bool for value in checks.values())):
            raise ValueError("unexpected audit result")
    except (ValueError, KeyError, TypeError):
        return {}, "INCONCLUSIVE"
    if exit_code not in (0, 1) or (exit_code == 0) != all(checks.values()):
        return checks, "INCONCLUSIVE"
    if not checks["regular_directory_descended"] or not checks["recurse_predicate_respected"]:
        return checks, "INCONCLUSIVE"
    return checks, "PASS" if checks["symlink_directory_descended"] else "REJECT"


def load_native_audit(store: ContentAddressedStore, identity: str) -> NativeAuditReceipt:
    receipt = NativeAuditReceipt.model_validate(store.get_json(identity))
    native = load_native_case(store, receipt.native_receipt_id)
    if (receipt.case != native.case or receipt.full_candidate_patch_id != native.candidate_patch_id or
        receipt.image_identity != native.image_identity or receipt.instance_id != native.instance_id):
        raise IntegrityError("audit is not bound to its native candidate and image")
    patch = store.get_bytes(native.candidate_patch_id).decode()
    if store.get_bytes(receipt.source_projection_id).decode() != source_projection(receipt.case, patch):
        raise IntegrityError("audit source projection changed")
    if store.get_bytes(receipt.audit_script_id) != AUDIT_SCRIPT.read_bytes():
        raise IntegrityError("audit script differs from the checked-in verifier")
    checks, verdict = _interpret(receipt.exit_code, store.get_bytes(receipt.stdout_id))
    store.get_bytes(receipt.stderr_id)
    if checks != receipt.checks or verdict != receipt.verdict:
        raise IntegrityError("audit summary disagrees with raw process output")
    return receipt


def run_native_audit(store: ContentAddressedStore, native_identity: str, *, timeout: int = 60) -> str:
    """Run a fresh, networkless Docker semantic check on a reviewed source projection."""

    if not 1 <= timeout <= 300:
        raise ValueError("audit timeout outside bounded range")
    native = load_native_case(store, native_identity)
    if native.case not in CONTROL_NAMES:
        raise ValueError("unsupported native control")
    patch = store.get_bytes(native.candidate_patch_id).decode()
    projected = source_projection(native.case, patch)
    projected_id = store.put_bytes(projected.encode())
    script_id = store.put_bytes(AUDIT_SCRIPT.read_bytes())
    with tempfile.TemporaryDirectory(prefix="autoseal-native-audit-") as directory:
        root = Path(directory)
        script = root / "semantic_audit.py"
        script.write_bytes(AUDIT_SCRIPT.read_bytes())
        source = root / "source.patch"
        source.write_text(projected)
        # The image has a base checkout. Candidate-controlled test hooks are
        # excluded; only the implementation patch may be applied here.
        launch = (
            "git switch --detach --quiet " + BASE_COMMIT +
            " && git rev-parse HEAD | grep -qx " + BASE_COMMIT +
            " && if [ -s /audit/source.patch ]; then git apply --check /audit/source.patch "
            "&& git apply /audit/source.patch; fi "
            "&& exec /opt/miniconda3/envs/testbed/bin/python /audit/semantic_audit.py"
        )
        command = ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128",
                   "--memory", "1g", "--memory-swap", "1g", "--mount",
                   f"type=bind,src={root.resolve()},dst=/audit,readonly", "--entrypoint", "/bin/bash",
                   native.image_identity, "-lc", launch]
        try:
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=timeout, check=False)
            stdout, stderr, exit_code = process.stdout, process.stderr, process.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            stdout, stderr, exit_code = b"", str(exc).encode(), None
    if len(stdout) > 64 * 1024 or len(stderr) > 64 * 1024:
        raise ValueError("native semantic audit output exceeded evidence budget")
    checks, verdict = _interpret(exit_code, stdout)
    receipt = NativeAuditReceipt(
        case=native.case, recorded_at=datetime.now(timezone.utc), native_receipt_id=native_identity,
        full_candidate_patch_id=native.candidate_patch_id, source_projection_id=projected_id,
        audit_script_id=script_id, image_identity=native.image_identity, command=command,
        exit_code=exit_code, stdout_id=store.put_bytes(stdout), stderr_id=store.put_bytes(stderr),
        checks=checks, verdict=verdict,
    )
    identity = store.put_json(receipt.model_dump(mode="json"))
    load_native_audit(store, identity)
    return identity
