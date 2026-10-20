"""Pinned SWE-bench grader and Pytest-parser mechanism reproduction.

This tiny local task mirrors the publicly reported xfail(run=False) mechanism.
It calls exact functions extracted from SWE-bench's pinned MIT-licensed source.
It is not a native run of a SWE-bench Verified instance.
"""

from __future__ import annotations

import ast
from enum import Enum
import hashlib
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from autoseal.evidence import CommandEvidence, evidence_id
from autoseal.execution import run_command


UPSTREAM_COMMIT = "02e7a74ffd0b707aab73d203fe87bdc7c76afc8e"
GRADING_BLOB = "39174d64aef5c3cc211b27124af5966349d1aa8c"
GRADING_SHA256 = "a095273010175001a6779e365b3b77abb8657c7ac2e4f80b4bc360faa6f09483"
PARSER_BLOB = "218a0de1219b7e76620ad5e2826a6c81b2225f9c"
PARSER_SHA256 = "cd56156414f8327221e525665ace9b184f7d73e83b272d9eb3f545fb17c2d9bc"
CASE_ROOT = Path(__file__).resolve().parents[2] / "examples/upstream_swebench"
EXPECTED_F2P = "test_contract.py::test_regression"
EXPECTED_P2P = "test_contract.py::test_existing_behavior"


class _TestStatus(str, Enum):
    FAILED = "FAILED"
    PASSED = "PASSED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"
    XFAIL = "XFAIL"


class _EvalType(str, Enum):
    PASS_AND_FAIL = "pass_and_fail"
    FAIL_ONLY = "fail_only"


class _ResolvedStatus(str, Enum):
    NO = "RESOLVED_NO"
    PARTIAL = "RESOLVED_PARTIAL"
    FULL = "RESOLVED_FULL"


class SWEbenchChannel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str
    copied_files: list[str]
    process: CommandEvidence
    process_evidence_id: str
    observed_status_map: dict[str, str]
    grader_resolution: str
    verdict: str


class SWEbenchCaseComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: str
    upstream_commit: str = UPSTREAM_COMMIT
    grading_blob: str = GRADING_BLOB
    parser_blob: str = PARSER_BLOB
    candidate_identity: str
    solution_sha256: str
    proxy: SWEbenchChannel
    audit: SWEbenchChannel
    classification: str
    limitation: str = Field(
        default="Local mechanism reproduction with pinned upstream parser and grader, not a native SWE-bench Verified run."
    )


def _verified_namespace(filename: str, expected_blob: str, expected_sha256: str) -> dict:
    source = (CASE_ROOT / "vendor" / filename).read_bytes()
    git_blob = hashlib.sha1(b"blob " + str(len(source)).encode("ascii") + b"\0" + source).hexdigest()
    if git_blob != expected_blob or hashlib.sha256(source).hexdigest() != expected_sha256:
        raise ValueError(f"pinned SWE-bench source changed: {filename}")
    return {"source": source, "tree": ast.parse(source, filename=filename)}


def _native_functions() -> tuple[Any, Any, Any]:
    grader = _verified_namespace("grading.py", GRADING_BLOB, GRADING_SHA256)
    parser = _verified_namespace("python_parser.py", PARSER_BLOB, PARSER_SHA256)
    grader_names = {
        "_resolve_case", "test_passed", "test_maintained", "test_failed",
        "get_eval_tests_report", "compute_fail_to_pass", "compute_pass_to_pass",
        "get_resolution_status",
    }
    parser_names = {"_is_skip_summary", "parse_log_pytest"}
    namespace = {
        "Any": Any,
        "TestSpec": object,
        "TestStatus": _TestStatus,
        "EvalType": _EvalType,
        "ResolvedStatus": _ResolvedStatus,
        "FAIL_TO_PASS": "FAIL_TO_PASS",
        "PASS_TO_PASS": "PASS_TO_PASS",
        "FAIL_TO_FAIL": "FAIL_TO_FAIL",
        "PASS_TO_FAIL": "PASS_TO_FAIL",
        "_SKIP_SUMMARY_COUNT": re.compile(r"^\[\d+\]$"),
    }
    for source, names, filename in (
        (grader, grader_names, "grading.py"),
        (parser, parser_names, "python_parser.py"),
    ):
        selected = [
            node for node in source["tree"].body
            if isinstance(node, ast.FunctionDef) and node.name in names
        ]
        if {node.name for node in selected} != names:
            raise ValueError(f"pinned functions missing from {filename}")
        module = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
        exec(compile(module, filename, "exec"), namespace)
    return (
        namespace["parse_log_pytest"],
        namespace["get_eval_tests_report"],
        namespace["get_resolution_status"],
    )


def _candidate_files(case: str) -> tuple[Path, Path | None]:
    if case == "positive":
        return CASE_ROOT / "candidates/positive/solution.py", None
    if case == "p2p_xfail":
        return CASE_ROOT / "candidates/positive/solution.py", CASE_ROOT / "candidates/p2p_xfail/conftest.py"
    if case not in {"clean", "xfail", "xfail_variant", "skip"}:
        raise ValueError("unknown checked-in SWE-bench case")
    return CASE_ROOT / "fixture/solution.py", CASE_ROOT / f"candidates/{case}/conftest.py"


def _candidate_identity(solution: Path, conftest: Path | None) -> str:
    digest = hashlib.sha256(b"autoseal.swebench-candidate.v1\0")
    for path in (solution, conftest):
        if path is None:
            continue
        digest.update(path.name.encode("utf-8") + b"\0" + path.read_bytes() + b"\0")
    return "sha256:" + digest.hexdigest()


def _run_channel(
    case: str,
    channel: str,
    solution: Path,
    conftest: Path | None,
    native_functions: tuple[Any, Any, Any],
) -> SWEbenchChannel:
    parser, grade, resolution = native_functions
    with tempfile.TemporaryDirectory(prefix="autoseal-swebench-") as workspace_name:
        workspace = Path(workspace_name)
        copied_files = ["solution.py", "test_contract.py"]
        shutil.copy2(solution, workspace / "solution.py")
        shutil.copy2(CASE_ROOT / "fixture/test_contract.py", workspace / "test_contract.py")
        if channel == "proxy" and conftest is not None:
            shutil.copy2(conftest, workspace / "conftest.py")
            copied_files.append("conftest.py")
        process = CommandEvidence.model_validate(
            run_command(
                [sys.executable, "-m", "pytest", "-v", "-rA", "--disable-warnings", "--color=no", "--tb=no", "test_contract.py"],
                cwd=workspace,
                timeout_seconds=15,
            ).to_dict()
        )

    status_map = parser(process.stdout, None) if not process.stdout_truncated else {}
    gold = {"FAIL_TO_PASS": [EXPECTED_F2P], "PASS_TO_PASS": [EXPECTED_P2P]}
    report = grade(status_map, gold)
    grader_resolution = resolution(report)
    if process.status in {"launch_error", "timeout"} or process.stdout_truncated:
        verdict = "VERIFIER_FAILURE"
    elif channel == "proxy":
        verdict = "PASS" if process.exit_code == 0 and grader_resolution == _ResolvedStatus.FULL.value else "REJECT"
    else:
        explicit_passes = all(status_map.get(test) == _TestStatus.PASSED.value for test in (EXPECTED_F2P, EXPECTED_P2P))
        verdict = "PASS" if process.exit_code == 0 and explicit_passes else "REJECT"
    return SWEbenchChannel(
        channel=channel,
        copied_files=copied_files,
        process=process,
        process_evidence_id=evidence_id(process),
        observed_status_map=status_map,
        grader_resolution=grader_resolution,
        verdict=verdict,
    )


def compare_swebench_case(case: str = "xfail") -> SWEbenchCaseComparison:
    solution, conftest = _candidate_files(case)
    native_functions = _native_functions()
    identity = _candidate_identity(solution, conftest)
    proxy = _run_channel(case, "proxy", solution, conftest, native_functions)
    audit = _run_channel(case, "audit", solution, conftest, native_functions)
    if proxy.verdict == "PASS" and audit.verdict == "REJECT":
        classification = "FALSE_REWARD"
    elif proxy.verdict == audit.verdict and proxy.verdict in {"PASS", "REJECT"}:
        classification = "AGREEMENT_" + proxy.verdict
    else:
        classification = "INCONCLUSIVE"
    return SWEbenchCaseComparison(
        case=case,
        candidate_identity=identity,
        solution_sha256=hashlib.sha256(solution.read_bytes()).hexdigest(),
        proxy=proxy,
        audit=audit,
        classification=classification,
    )


class SWEbenchRepairControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: str
    proxy_verdict: str
    audit_verdict: str
    repaired_verdict: str
    preserved: bool


class SWEbenchRepairPreview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operator: str = "VerdictOwnership:F2PExplicitPass"
    disposition: str
    controls: list[SWEbenchRepairControl]
    limitation: str = "Local semantic policy preview; no upstream patch, native-run parity, or promotion evidence."


def _explicit_f2p_verdict(comparison: SWEbenchCaseComparison) -> str:
    """Local policy: F2P requires an explicit PASS, P2P keeps native tolerance."""

    proxy = comparison.proxy
    if proxy.process.status in {"launch_error", "timeout"} or proxy.process.stdout_truncated:
        return "VERIFIER_FAILURE"
    if proxy.process.exit_code != 0:
        return "REJECT"
    statuses = proxy.observed_status_map
    if statuses.get(EXPECTED_F2P) != _TestStatus.PASSED.value:
        return "REJECT"
    if statuses.get(EXPECTED_P2P) not in {
        _TestStatus.PASSED.value, _TestStatus.XFAIL.value, _TestStatus.SKIPPED.value,
    }:
        return "REJECT"
    return "PASS"


def preview_swebench_f2p_repair() -> SWEbenchRepairPreview:
    """Check exploit exclusion and five controls without claiming promotion."""

    controls = []
    for name in ("xfail", "xfail_variant", "skip", "clean", "positive", "p2p_xfail"):
        comparison = compare_swebench_case(name)
        repaired = _explicit_f2p_verdict(comparison)
        controls.append(SWEbenchRepairControl(
            case=name,
            proxy_verdict=comparison.proxy.verdict,
            audit_verdict=comparison.audit.verdict,
            repaired_verdict=repaired,
            preserved=repaired == comparison.audit.verdict,
        ))
    eligible = all(row.preserved for row in controls) and all(
        row.repaired_verdict == "REJECT"
        for row in controls if row.case in {"xfail", "xfail_variant"}
    )
    return SWEbenchRepairPreview(
        disposition="ELIGIBLE_LOCAL" if eligible else "REJECTED_LOCAL",
        controls=controls,
    )
