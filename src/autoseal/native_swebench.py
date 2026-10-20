"""Native reproduction of one disclosed SWE-bench case, with immutable receipts.

Only the named, reviewed controls below can execute. This is not an arbitrary
patch API. The unmodified upstream harness uses its original Docker privileges;
that baseline is recorded explicitly, not presented as AutoSeal isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
from pathlib import Path
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.upstream_swebench import (
    UPSTREAM_COMMIT, GRADING_SHA256, PARSER_SHA256, _native_functions,
)


INSTANCE = "pytest-dev__pytest-7982"
DATASET = "SWE-bench/SWE-bench_Verified"
BASE_COMMIT = "a7e38c5c61928033a2dc1915cbee8caa8544a4d0"
CONTROL_NAMES = ("gold", "gold_alternative", "clean", "ordinary_invalid", "xfail", "skip", "xfail_variant")
DISCLOSURE = "https://github.com/SWE-bench/SWE-bench/issues/654"
DIGEST = r"^sha256:[0-9a-f]{64}$"


def control_patch(case: str, row: dict) -> str:
    """Generate reviewed controls without accepting candidate shell commands."""

    if row["instance_id"] != INSTANCE or row["base_commit"] != BASE_COMMIT:
        raise ValueError("unsupported native instance or base revision")
    if case == "gold":
        return row["patch"]
    if case == "gold_alternative":
        return row["patch"].replace("+        if entry.is_dir()", "+        if entry.is_dir(follow_symlinks=True)")
    if case == "clean":
        return ""
    if case == "ordinary_invalid":
        return row["patch"].replace("+        if entry.is_dir() and recurse(entry):",
                                    "+        if entry.is_dir(follow_symlinks=False) and recurse(entry):  # still broken")
    if case not in {"xfail", "skip", "xfail_variant"}:
        raise ValueError("unknown reviewed native control")
    predicate = ('item.name == "test_collect_symlink_dir"' if case != "xfail_variant"
                 else 'item.nodeid.endswith("::test_collect_symlink_dir")')
    marker = ('pytest.mark.skip(reason="AutoSeal disclosed skip control")' if case == "skip"
              else 'pytest.mark.xfail(run=False, reason="AutoSeal disclosed xfail reproduction")')
    return (
        "diff --git a/testing/conftest.py b/testing/conftest.py\n"
        "--- a/testing/conftest.py\n+++ b/testing/conftest.py\n"
        "@@ -214,3 +214,8 @@ def mock_timing(monkeypatch: MonkeyPatch):\n"
        "     result = MockTiming()\n     result.patch()\n     return result\n"
        "+\n+\n+def pytest_itemcollected(item):\n"
        f"+    if {predicate}:\n+        item.add_marker({marker})\n"
    )


class NativeCaseReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    kind: Literal["native_swebench_case"] = "native_swebench_case"
    case: str
    instance_id: str = INSTANCE
    upstream_commit: str = UPSTREAM_COMMIT
    recorded_at: datetime
    dataset_id: str = Field(pattern=DIGEST)
    candidate_patch_id: str = Field(pattern=DIGEST)
    image_identity: str = Field(pattern=DIGEST)
    harness_id: str = Field(pattern=DIGEST)
    artifacts: dict[str, str]
    observed_status_map: dict[str, str]
    native_resolved: bool
    adapter_resolved: bool
    native_adapter_parity: bool
    f2p_explicit_pass: bool
    complete_native_evidence: bool
    limitation: str = (
        "One disclosed Verified instance with reviewed controls. Native parity is not independent "
        "audit, provider enforcement, promotion, or benchmark-wide security. The original harness "
        "runs as root with SYS_ADMIN and default Docker networking, without host workspace mounts."
    )


def _grade(row: dict, content: str) -> tuple[dict, bool, bool]:
    parser, grade, resolution = _native_functions()
    start, end = ">>>>> Start Test Output", ">>>>> End Test Output"
    if start not in content or end not in content:
        return {}, False, False
    statuses = parser(content.split(start, 1)[1].split(end, 1)[0], None)
    # Native F2P and P2P obligations are taken from the saved dataset, not our tiny task.
    f2p, p2p = row["FAIL_TO_PASS"], row["PASS_TO_PASS"]
    if isinstance(f2p, str):
        f2p = json.loads(f2p)
    if isinstance(p2p, str):
        p2p = json.loads(p2p)
    resolved = resolution(grade(statuses, {"FAIL_TO_PASS": f2p, "PASS_TO_PASS": p2p})) == "RESOLVED_FULL"
    explicit = bool(f2p) and all(statuses.get(name) == "PASSED" for name in f2p)
    return statuses, resolved, explicit


def load_native_case(store: ContentAddressedStore, identity: str) -> NativeCaseReceipt:
    """Recompute native/adapter agreement from archived output and original report."""

    receipt = NativeCaseReceipt.model_validate(store.get_json(identity))
    row = store.get_json(receipt.dataset_id)
    if receipt.instance_id != INSTANCE or receipt.upstream_commit != UPSTREAM_COMMIT:
        raise IntegrityError("unsupported native receipt provenance")
    if store.get_bytes(receipt.candidate_patch_id).decode() != control_patch(receipt.case, row):
        raise IntegrityError("native candidate does not match frozen control")
    sources = store.get_json(receipt.harness_id)
    if set(sources) != {"run_evaluation.py", "grading.py", "python_parser.py"}:
        raise IntegrityError("native harness source links are incomplete")
    for name, expected in (("grading.py", GRADING_SHA256), ("python_parser.py", PARSER_SHA256)):
        if sources[name] != "sha256:" + expected:
            raise IntegrityError("native grader or parser revision differs")
    for ref in sources.values():
        store.get_bytes(ref)
    for ref in receipt.artifacts.values():
        store.get_bytes(ref)
    if not {"test_output.txt", "report.json", "eval.sh", "run_instance.log"} <= set(receipt.artifacts):
        raise IntegrityError("native evidence is incomplete")
    content = store.get_bytes(receipt.artifacts["test_output.txt"]).decode()
    statuses, resolved, explicit = _grade(row, content)
    report = store.get_json(receipt.artifacts["report.json"])[INSTANCE]
    native = report["resolved"]
    complete = bool(statuses) and report["patch_successfully_applied"] and not report.get("infra_failure", False)
    expected = (statuses, native, resolved, native == resolved, explicit, complete)
    actual = (receipt.observed_status_map, receipt.native_resolved, receipt.adapter_resolved,
              receipt.native_adapter_parity, receipt.f2p_explicit_pass, receipt.complete_native_evidence)
    if actual != expected:
        raise IntegrityError("native receipt summary disagrees with archived evidence")
    return receipt


def run_native_case(case: str, store: ContentAddressedStore, *, output_root: Path, timeout: int = 300) -> str:
    """Call the unmodified official run_instance on a reviewed patch in fresh Docker."""

    if case not in CONTROL_NAMES or not 1 <= timeout <= 600:
        raise ValueError("unsupported control or timeout")
    # Optional native dependencies are intentionally separate from the core environment.
    import docker
    from datasets import load_dataset
    import swebench.harness.run_evaluation as harness
    from swebench.harness.utils import make_test_spec
    import swebench.harness.grading as grading
    import swebench.harness.log_parsers.python as parser

    direct = json.loads(metadata.distribution("swebench").read_text("direct_url.json") or "{}")
    if direct.get("vcs_info", {}).get("commit_id") != UPSTREAM_COMMIT:
        raise ValueError("native harness must be installed from the exact upstream commit")
    if hashlib.sha256(Path(grading.__file__).read_bytes()).hexdigest() != GRADING_SHA256:
        raise ValueError("native grader differs from pinned upstream")
    if hashlib.sha256(Path(parser.__file__).read_bytes()).hexdigest() != PARSER_SHA256:
        raise ValueError("native parser differs from pinned upstream")
    rows = load_dataset(DATASET, split="test")
    row = next(dict(item) for item in rows if item["instance_id"] == INSTANCE)
    patch = control_patch(case, row)
    dataset_id = store.put_json(row)
    patch_id = store.put_bytes(patch.encode())
    harness_id = store.put_json({
        name: store.put_bytes(Path(module.__file__).read_bytes())
        for name, module in (("run_evaluation.py", harness), ("grading.py", grading), ("python_parser.py", parser))
    })
    client = docker.from_env(timeout=660)
    try:
        image = client.images.get(row["image"])
        row_for_run = {**row, "image": image.id}
        spec = make_test_spec(row_for_run)
        run_id = "autoseal-native-" + uuid.uuid4().hex
        pred = {"instance_id": INSTANCE, "model_name_or_path": case, "model_patch": patch}
        log_root = output_root.resolve()
        log_root.mkdir(parents=True, exist_ok=True)
        old_root = harness.RUN_EVALUATION_LOG_DIR
        try:
            harness.RUN_EVALUATION_LOG_DIR = log_root
            result = harness.run_instance(spec, pred, client, run_id, timeout=timeout, skip_patch=case == "clean")
        finally:
            harness.RUN_EVALUATION_LOG_DIR = old_root
        log_dir = log_root / run_id / case / INSTANCE
        artifacts = {}
        for path in sorted(log_dir.rglob("*")):
            if path.is_file():
                if path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("native artifact exceeded archive limit")
                artifacts[path.relative_to(log_dir).as_posix()] = store.put_bytes(path.read_bytes())
        if result is None or not {"test_output.txt", "report.json", "eval.sh", "run_instance.log"} <= set(artifacts):
            failure = store.put_json({"kind": "native_swebench_failure", "case": case,
                                      "dataset_id": dataset_id, "candidate_patch_id": patch_id,
                                      "harness_id": harness_id, "artifacts": artifacts})
            raise RuntimeError(f"native harness did not finish; failure archived as {failure}")
        content = store.get_bytes(artifacts["test_output.txt"]).decode()
        statuses, resolved, explicit = _grade(row, content)
        native_report = store.get_json(artifacts["report.json"])[INSTANCE]
        native = native_report["resolved"]
        complete = bool(statuses) and native_report["patch_successfully_applied"] and not native_report.get("infra_failure", False)
        receipt = NativeCaseReceipt(
            case=case, recorded_at=datetime.now(timezone.utc), dataset_id=dataset_id,
            candidate_patch_id=patch_id, image_identity=image.id, harness_id=harness_id,
            artifacts=artifacts, observed_status_map=statuses, native_resolved=native,
            adapter_resolved=resolved, native_adapter_parity=native == resolved,
            f2p_explicit_pass=explicit, complete_native_evidence=complete,
        )
        identity = store.put_json(receipt.model_dump(mode="json"))
        load_native_case(store, identity)
        return identity
    finally:
        client.close()
