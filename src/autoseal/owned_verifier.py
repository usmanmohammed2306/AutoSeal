"""Manager-owned behavioral verification of the registered is_even fixture.

Only the candidate's solution bytes enter Docker. The manager holds expected
answers, interprets untrusted outputs, and owns the result store. Incomplete
candidate execution stays inconclusive, never a successful exploit block.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import uuid

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.docker_profile import readonly_python_command
from autoseal.execution import CommandStatus, run_command
from autoseal.local_demo import FIXTURE, candidate_identity
from autoseal.projection import project_candidate_artifacts
from autoseal.storage import ContentAddressedStore, IntegrityError


WORKER = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location('candidate_solution', '/candidate/solution.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
values = json.loads(sys.argv[1])
answers = [module.is_even(value) for value in values]
print(json.dumps(answers, allow_nan=False))
"""
INPUTS = (0, 1, 2, -1, -2, 17, 42)
AUDIT_INPUTS = (-1001, -1000, -3, 3, 1000, 1001, 2**60, 2**60 + 1)
CONTROLS = frozenset({"positive", "positive_alternative", "negative", "negative_alternative",
                      "exploit", "exploit_variant", "exploit_holdout", "exit_spoof"})


def inspect_enforcement(body: dict, *, image: str, candidate_root: Path) -> dict[str, bool]:
    """Interpret Docker-daemon metadata, not candidate-reported capabilities."""

    host = body.get("HostConfig", {})
    mounts = body.get("Mounts", [])
    return {
        "pinned_image": body.get("Image") == image,
        "nonroot_user": body.get("Config", {}).get("User") == "65534:65534",
        "network_disabled": host.get("NetworkMode") == "none",
        "root_read_only": host.get("ReadonlyRootfs") is True,
        "capabilities_dropped": host.get("CapDrop") == ["ALL"],
        "no_new_privileges": "no-new-privileges" in host.get("SecurityOpt", []),
        "bounded_memory": host.get("Memory") == 512 * 1024 * 1024,
        "bounded_pids": host.get("PidsLimit") == 128,
        "bounded_cpu": host.get("NanoCpus") == 1_000_000_000,
        "only_candidate_mount": len(mounts) == 1 and all(
            item.get("Type") == "bind" and item.get("Source") == str(candidate_root) and
            item.get("Destination") == "/candidate" and item.get("RW") is False for item in mounts),
    }


def interpret_answers(process: dict, inputs: tuple[int, ...], *, audit: bool) -> dict:
    """Count actual wrong boolean answers only; reject no incomplete executions."""

    empty = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    if process["status"] not in {"exited_zero", "exited_nonzero"}:
        return {"verdict": "INFRASTRUCTURE_FAILURE", "counts": empty, "reason": "execution did not finish"}
    if (process["status"] != "exited_zero" or process["stdout_truncated"] or
            process["stderr_truncated"]):
        return {"verdict": "INCONCLUSIVE", "counts": empty, "reason": "candidate execution incomplete"}
    try:
        answers = json.loads(process["stdout"])
        if (not isinstance(answers, list) or len(answers) != len(inputs) or
                any(type(answer) is not bool for answer in answers)):
            raise ValueError("expected exactly one boolean result per input")
    except (ValueError, TypeError):
        return {"verdict": "INCONCLUSIVE", "counts": empty, "reason": "invalid candidate output protocol"}
    # The audit's bitwise reference and inputs are separate from the visible
    # modulo contract. Neither reference is imported by the candidate process.
    expected = [((value & 1) == 0) if audit else (value % 2 == 0) for value in inputs]
    passed = sum(actual == wanted for actual, wanted in zip(answers, expected))
    return {"verdict": "PASS" if passed == len(inputs) else "REJECT",
            "counts": {**empty, "passed": passed, "failed": len(inputs) - passed},
            "reason": "manager compared observed boolean outputs against task obligations"}


def evaluate_owned_fixture(candidate: str, channel: str, store: ContentAddressedStore,
                           *, image: str = DEFAULT_IMAGE) -> str:
    if candidate not in CONTROLS or channel not in {"audit", "sealed"}:
        raise ValueError("only registered fixture candidates and audit/sealed channels are supported")
    original = FIXTURE / "candidates" / candidate
    return evaluate_owned_candidate(original, candidate, channel, store, image=image)


def evaluate_owned_candidate(original: Path, candidate: str, channel: str, store: ContentAddressedStore,
                             *, image: str = DEFAULT_IMAGE) -> str:
    """Internal manager entry point for an already frozen local candidate.

    No HTTP endpoint accepts a filesystem path or arbitrary source here.
    """

    if channel not in {"audit", "sealed"}:
        raise ValueError("unknown owned-verifier channel")
    inputs = AUDIT_INPUTS if channel == "audit" else INPUTS
    result = execute_owned_payload(original, candidate, store, image=image, worker=WORKER, payload=list(inputs))
    interpreted = interpret_answers(result["process"], inputs, audit=channel == "audit")
    return store.put_json({**result, "kind": "owned_fixture_evaluation", "channel": channel, **interpreted})


def execute_owned_payload(original: Path, candidate: str, store: ContentAddressedStore,
                          *, image: str, worker: str, payload) -> dict:
    """Run a manager-selected worker under the exact owned-candidate profile.

    This is internal infrastructure shared by behavioral evaluation and its
    trusted capability probe. Worker code is never accepted through the API.
    """

    frozen_identity = candidate_identity(original)
    image_id = image_identity(image)
    name = "autoseal-owned-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="autoseal-owned-") as temporary:
        source = Path(temporary) / "candidate"
        source.mkdir()
        project_candidate_artifacts(original, source, ("solution.py",))
        create = readonly_python_command(name, source, image_id, worker, payload)
        created = run_command(create, timeout_seconds=15, max_output_bytes=4096)
        if created.status is not CommandStatus.EXITED_ZERO:
            raise RuntimeError("unable to create owned verifier container")
        try:
            inspected = run_command(["docker", "inspect", name], timeout_seconds=10, max_output_bytes=64 * 1024)
            if inspected.status is not CommandStatus.EXITED_ZERO or inspected.stdout_truncated:
                raise IntegrityError("cannot verify candidate container enforcement")
            body = json.loads(inspected.stdout)
            if not isinstance(body, list) or len(body) != 1:
                raise IntegrityError("unexpected container inspection")
            gates = inspect_enforcement(body[0], image=image_id, candidate_root=source)
            if not all(gates.values()):
                raise IntegrityError("candidate container enforcement differs from requested policy")
            process = run_command(["docker", "start", "--attach", name], timeout_seconds=10,
                                  max_output_bytes=16 * 1024)
        finally:
            removed = run_command(["docker", "rm", "-f", name], timeout_seconds=10, max_output_bytes=4096)
            if removed.status is not CommandStatus.EXITED_ZERO:
                raise RuntimeError("candidate container cleanup failed")
        projected_source = (source / "solution.py").read_bytes()
    if candidate_identity(original) != frozen_identity:
        raise IntegrityError("candidate changed during evaluation")
    result = {
        "schema_version": 1, "candidate": candidate,
        "candidate_identity": frozen_identity, "image_identity": image_id,
        "source_identity": store.put_bytes(projected_source), "worker_identity": store.put_bytes(worker.encode()),
        "projected_files": ["solution.py"],
        "inputs_identity": store.put_json(payload), "enforcement": gates,
        "inspection_id": store.put_json(inspected.to_dict()), "creation_id": store.put_json(created.to_dict()),
        "cleanup_id": store.put_json(removed.to_dict()),
        "container_inspection": body[0],
        "process_id": store.put_json(process.to_dict()), "process": process.to_dict(),
        "owner": "trusted_manager", "limitation": "Finite is_even behavior checks, not universal semantic correctness or hostile-code isolation.",
    }
    return result
