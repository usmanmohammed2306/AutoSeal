"""Synthetic transport receipts test the offline verifier, not Docker safety."""

import copy
import json
from pathlib import Path

import pytest

from autoseal.execution import CommandResult, CommandStatus
from autoseal.managed_receipts import load_candidate_snapshot, snapshot_candidate, verify_runtime_result
from autoseal.owned_verifier import INPUTS, WORKER, inspect_enforcement, interpret_answers
from autoseal.storage import ContentAddressedStore, IntegrityError


def receipt(command, stdout, *, exit_code=0):
    return CommandResult(tuple(command), CommandStatus.EXITED_ZERO if exit_code == 0 else
                         CommandStatus.EXITED_NONZERO, exit_code, stdout, "", False, False).to_dict()


def sample(tmp_path):
    store = ContentAddressedStore(tmp_path / "evidence")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "solution.py").write_text("def is_even(value):\n    return True\n")
    snapshot = snapshot_candidate(store, candidate)
    image, name, container = "sha256:" + "1" * 64, "unit-only", "f" * 64
    mount_root = "/unit-only/projected"
    body = {"Id": container, "Name": "/" + name, "Image": image,
            "Config": {"User": "65534:65534", "Entrypoint": ["python"],
                       "Cmd": ["-I", "-c", WORKER, json.dumps(INPUTS)]},
            "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"], "Memory": 512 * 1024 * 1024,
                "PidsLimit": 128, "NanoCpus": 1_000_000_000},
            "Mounts": [{"Type": "bind", "Source": mount_root, "Destination": "/candidate", "RW": False}]}
    process = receipt(["docker", "start", "--attach", name], json.dumps([True] * len(INPUTS)))
    result = {"candidate_identity": snapshot["candidate_identity"], "channel": "sealed",
        "image_identity": image, "source_identity": snapshot["files"]["solution.py"],
        "process": process, "process_id": store.put_json(process),
        "creation_id": store.put_json(receipt(["docker", "create", "--name", name, "--mount",
            f"type=bind,src={mount_root},dst=/candidate,readonly"], container + "\n")),
        "inspection_id": store.put_json(receipt(["docker", "inspect", name], json.dumps([body]))),
        "cleanup_id": store.put_json(receipt(["docker", "rm", "-f", name], name + "\n")),
        "container_inspection": body, "worker_identity": store.put_bytes(WORKER.encode()),
        "inputs_identity": store.put_json(list(INPUTS)), "projected_files": ["solution.py"],
        "owner": "trusted_manager", "enforcement": inspect_enforcement(body, image=image, candidate_root=Path(mount_root)),
        **interpret_answers(process, INPUTS, audit=False)}
    return store, snapshot, result


def check(store, snapshot, result):
    return verify_runtime_result(store, result, snapshot, image=result["image_identity"], channel="sealed")


def test_offline_verification_derives_counts_and_never_executes_candidates(tmp_path, monkeypatch):
    store, snapshot, result = sample(tmp_path)
    def forbidden(*args, **kwargs):
        raise AssertionError("offline evidence verification started a process")
    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("autoseal.owned_verifier.run_command", forbidden)
    observed = check(store, snapshot, result)
    assert observed["verdict"] == "REJECT"
    assert observed["counts"]["failed"] == 3
    assert load_candidate_snapshot(store, snapshot)["solution.py"].startswith(b"def is_even")


@pytest.mark.parametrize("change", [
    "counts", "verdict", "source", "worker", "inputs", "inspection_summary", "raw_inspection",
    "cleanup", "create", "inspect_command", "process_command", "truncated_output", "forged_output",
])
def test_rehashed_summaries_cannot_override_raw_receipts(tmp_path, change):
    store, snapshot, result = sample(tmp_path)
    result = copy.deepcopy(result)
    if change == "counts":
        result["counts"]["failed"] = 0
    elif change == "verdict":
        result["verdict"] = "PASS"
    elif change == "source":
        result["source_identity"] = store.put_bytes(b"another solution")
    elif change == "worker":
        result["worker_identity"] = store.put_bytes(b"print('PASS')")
    elif change == "inputs":
        result["inputs_identity"] = store.put_json([0])
    elif change == "inspection_summary":
        result["container_inspection"]["HostConfig"]["NetworkMode"] = "host"
    elif change == "raw_inspection":
        result["container_inspection"]["HostConfig"]["NetworkMode"] = "host"
        raw = store.get_json(result["inspection_id"])
        raw["stdout"] = json.dumps([result["container_inspection"]])
        result["inspection_id"] = store.put_json(raw)
    elif change in {"cleanup", "create", "inspect_command"}:
        key = {"cleanup": "cleanup_id", "create": "creation_id", "inspect_command": "inspection_id"}[change]
        raw = store.get_json(result[key])
        if change == "cleanup":
            raw.update(status="exited_nonzero", exit_code=1, stdout="")
        elif change == "create":
            raw["stdout"] = "b" * 64
        else:
            raw["command"][-1] = "different-container"
        result[key] = store.put_json(raw)
    else:
        raw = result["process"]
        if change == "process_command":
            raw["command"] = ["echo", "PASS"]
        elif change == "truncated_output":
            raw["stdout_truncated"] = True
        else:
            raw["stdout"] = '{"verdict":"REJECT","failed":7}'
        result["process_id"] = store.put_json(raw)
    with pytest.raises(IntegrityError):
        check(store, snapshot, result)


def test_candidate_manifest_includes_hook_bytes_and_refuses_missing_or_changed_objects(tmp_path):
    store, snapshot, _ = sample(tmp_path)
    changed = copy.deepcopy(snapshot)
    changed["files"]["conftest.py"] = store.put_bytes(b"# candidate hook\n")
    with pytest.raises(IntegrityError, match="frozen identity"):
        load_candidate_snapshot(store, changed)
    changed["files"]["../solution.py"] = changed["files"].pop("solution.py")
    with pytest.raises(IntegrityError, match="snapshot contract"):
        load_candidate_snapshot(store, changed)
    digest = snapshot["files"]["solution.py"][7:]
    (store.root / "objects" / digest[:2] / digest).write_bytes(b"changed on disk")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        load_candidate_snapshot(store, snapshot)
