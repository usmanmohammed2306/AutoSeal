"""Verify the disclosed task-125 native-test reproduction without executing it.

The closed receipt format pins the reviewed worker and frozen controls. This
does not admit a repair, run the official benchmark harness, or generalize the
single reproduced task into a benchmark-wide rate.
"""

from __future__ import annotations

import json
from pathlib import Path

from autoseal.artifact_runtime import load_files
from autoseal.evidence import CommandEvidence
from autoseal.local_demo import _counts
from autoseal.storage import ContentAddressedStore, IntegrityError


REVISION = "d8a29613235a0ef56a8b70b3142626a533da28c2"
WORKER_ID = "sha256:943a6e01a6069a5dd0526b7f03e57f167be159a82a7261a853eca8ac2403c9a2"
CORPUS_ID = "sha256:8db2894fe3f596673539ce8d0d1c6ceeafa87e8a8341ff478aba24223079548d"
TEST_SHA256 = "1a85448e1d9bb9c029f7822965709a017f82d2eb3adcc689f3e8f35e093eeb3b"


def _execution(store, identity, *, candidate, channel, image):
    receipt = store.get_json(identity)
    if (receipt["kind"] != "reviewed_shell_native_test_execution" or receipt["candidate_id"] != candidate
            or receipt["image"] != image or receipt["channel"] != channel or receipt["worker_id"] != WORKER_ID):
        raise IntegrityError("native-test receipt differs from its frozen context")
    load_files(store, candidate)
    worker = store.get_bytes(WORKER_ID).decode()
    raw = {name: store.get_json(ref) for name, ref in receipt["raw"].items()}
    if set(raw) != {"create", "inspect", "process", "cleanup"}:
        raise IntegrityError("native-test lifecycle is incomplete")
    for process in raw.values():
        CommandEvidence.model_validate(process)
        if process["status"] != "exited_zero" or process["stdout_truncated"] or process["stderr_truncated"]:
            raise IntegrityError("native-test lifecycle did not complete")
    bodies = json.loads(raw["inspect"]["stdout"])
    if len(bodies) != 1:
        raise IntegrityError("native-test inspection must name one container")
    body = bodies[0]
    name = body["Name"].removeprefix("/")
    mounts = body["Mounts"]
    if len(mounts) != 1 or mounts[0]["Destination"] != "/candidate" or mounts[0]["RW"]:
        raise IntegrityError("native-test candidate mount differs")
    command = ["docker", "create", "--name", name, "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1", "--pids-limit", "128", "--mount", f"type=bind,src={mounts[0]['Source']},dst=/candidate,readonly"]
    if channel != "proxy":
        command += ["--read-only", "--user", "65534:65534", "--tmpfs", "/app:rw,nosuid,nodev,size=64m,uid=65534,gid=65534",
                    "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m,uid=65534,gid=65534"]
    payload = json.dumps({"channel": channel, "test_sha256": TEST_SHA256})
    command += ["--entrypoint", "/opt/autoseal-verifier/bin/python", image, "-I", "-c", worker, payload]
    host = body["HostConfig"]
    if (raw["create"]["command"] != command or raw["create"]["stdout"].strip() != body["Id"]
            or raw["inspect"]["command"] != ["docker", "inspect", name]
            or raw["process"]["command"] != ["docker", "start", "--attach", name]
            or raw["cleanup"]["command"] != ["docker", "rm", "-f", name]
            or raw["cleanup"]["stdout"].strip() != name or body["Image"] != image
            or host["NetworkMode"] != "none" or host["Privileged"]
            or host["Memory"] != 536870912 or host["MemorySwap"] != 536870912
            or host["PidsLimit"] != 128 or host["NanoCpus"] != 1000000000
            or host["CapDrop"] != ["ALL"] or host["SecurityOpt"] != ["no-new-privileges"]
            or body["Config"]["Entrypoint"] != ["/opt/autoseal-verifier/bin/python"]
            or body["Config"]["Cmd"] != ["-I", "-c", worker, payload]
            or (channel != "proxy" and (not host["ReadonlyRootfs"] or body["Config"]["User"] != "65534:65534"))):
        raise IntegrityError("native-test lifecycle/profile linkage failed")
    observed = json.loads(raw["process"]["stdout"])
    if (observed["channel"] != channel or observed["native_test_sha256"] != TEST_SHA256
            or any(observed[key] != receipt[key] for key in ("result", "runtime_fingerprints", "native_test_sha256"))):
        raise IntegrityError("native-test outcome differs from raw output")
    result = observed["result"]
    if channel == "audit":
        if set(result["checks"]) != {"scripts_complete", "backup_bytes", "deployment", "processed_rows"}:
            raise IntegrityError("audit obligations changed")
        if any(type(value) is not bool for value in result["checks"].values()) or len(result["commands"]) != 3:
            raise IntegrityError("audit evidence is incomplete")
        expected = "PASS" if all(result["checks"].values()) else "REJECT"
    else:
        counts = _counts(result["stdout"])
        if counts["errors"] or counts["skipped"] or counts["passed"] + counts["failed"] != 3:
            raise IntegrityError("native tests did not complete all three obligations")
        if result["exit_code"] == 0 and counts["passed"] == 3:
            expected = "PASS"
        elif result["exit_code"] == 1 and counts["failed"] > 0:
            expected = "REJECT"
        else:
            raise IntegrityError("native verifier crash is not a task rejection")
    if result["verdict"] != expected:
        raise IntegrityError("native-test verdict contradicts checked evidence")
    return observed


def verify_shell_report(store: ContentAddressedStore, identity: str):
    report = store.get_json(identity)
    if (report["kind"] != "task_125_native_test_reproduction" or report["schema_version"] != 1
            or report["source_revision"] != REVISION or report["corpus_id"] != CORPUS_ID):
        raise IntegrityError("unsupported external native-test report")
    corpus = store.get_json(CORPUS_ID)
    for ref in report["sources"].values():
        store.get_bytes(ref)
    if len(report["rows"]) != 8:
        raise IntegrityError("native-test controls are missing")
    checked, runtime = [], None
    for control, row in zip(corpus["controls"], report["rows"]):
        if row["name"] != control["name"] or row["role"] != control["role"] or set(row["channels"]) != {"proxy", "audit", "sealed"}:
            raise IntegrityError("native-test controls or channels differ from frozen corpus")
        channels = {}
        for channel, ref in row["channels"].items():
            observed = _execution(store, ref["identity"], candidate=control["candidate_id"], channel=channel, image=report["image"])
            if observed["result"]["verdict"] != ref["verdict"]:
                raise IntegrityError("native-test summary contradicts its receipt")
            channels[channel] = observed
        if runtime is None:
            runtime = channels["audit"]["runtime_fingerprints"]
        if any(channels[c]["runtime_fingerprints"] != runtime for c in ("audit", "sealed")):
            raise IntegrityError("clean runtime fingerprint changed across controls")
        expected = "PASS" if control["role"] == "positive" else "REJECT"
        if channels["audit"]["result"]["verdict"] != expected or channels["sealed"]["result"]["verdict"] != expected:
            raise IntegrityError("native-test preservation or audit control failed")
        if row["audit_expected"] is not True or row["sealed_expected"] is not True:
            raise IntegrityError("native-test summary gate differs")
        if control["role"] in {"exploit", "development", "heldout"}:
            if channels["proxy"]["result"]["verdict"] != "PASS" or channels["proxy"]["runtime_fingerprints"] == runtime:
                raise IntegrityError("disclosed native runtime hijack did not reproduce")
        elif channels["proxy"]["result"]["verdict"] != expected:
            raise IntegrityError("native unaffected control parity failed")
        checked.append({"name": control["name"], "role": control["role"],
            **{channel: value["result"]["verdict"] for channel, value in channels.items()}})
    if report["status"] != "PASSED" or report["error"] is not None:
        raise IntegrityError("native-test report is not complete")
    return {"report_id": identity, "source_revision": REVISION, "image": report["image"], "controls": checked,
        "scope": "One disclosed task, unchanged native tests with adapted dependency bootstrap; no official harness score or promoted repair.",
        "discovery_credit": "TerminalWrench public reporters", "limitations": report["limitations"]}


def load_shell_archive(root: Path):
    index = json.loads((root / "report.json").read_text())
    return verify_shell_report(ContentAddressedStore(root / "evidence"), index["report_id"])
