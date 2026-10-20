"""Function-level replay of the pinned SWE-Smith missing-test grading defect.

The two source files are byte-for-byte copies of the public MIT-licensed
upstream grader before and after SWE-Smith's fix for issue 24. We extract
only the grading functions. No candidate code or arbitrary external source
is executed here. This is not a full SWE-Smith benchmark run.
"""

from __future__ import annotations

import ast
from enum import Enum
import hashlib
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field


UPSTREAM_REPOSITORY = "https://github.com/SWE-bench/SWE-smith"
PRE_FIX_COMMIT = "d8b20f3f2ee13e8c9b6ef9495c25e9704008d07a"
POST_FIX_COMMIT = "fd89801ac1be6433339034710cdb7a27f87b673e"
PRE_FIX_BLOB = "0e66033191a1127091f26a0e2e83c6539c7606a0"
POST_FIX_BLOB = "2ada8471163de9e1e8cd70d6fe75a9954518367c"
PRE_FIX_SHA256 = "816d87916325df167c1e8eff1842c52ac16a0e2a9f179919d2a1b4f9aeea4fb6"
POST_FIX_SHA256 = "368bfb82317b4d3059de3f255183cd4fcc302697b82a7980720d0e4bb568d1ec"
FIXTURE_DIRECTORY = Path(__file__).resolve().parents[2] / "examples/upstream_swesmith/vendor"

FAIL_TO_PASS = "FAIL_TO_PASS"
PASS_TO_PASS = "PASS_TO_PASS"
FAIL_TO_FAIL = "FAIL_TO_FAIL"
PASS_TO_FAIL = "PASS_TO_FAIL"


class _TestStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"
    XFAIL = "XFAIL"


class UpstreamGraderOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_commit: str
    source_blob: str
    channel: str
    verdict: str
    f2p_success: list[str]
    f2p_failure: list[str]
    p2p_success: list[str]
    p2p_failure: list[str]


class UpstreamGraderComparison(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case: str
    expected_tests: list[str]
    observed_status_map: dict[str, str]
    execution_health: str
    historical_proxy: UpstreamGraderOutcome
    repaired_control: UpstreamGraderOutcome
    classification: str
    limitation: str = Field(
        default="Function-level reproduction of original grader code, not a full upstream agent run."
    )


def _git_blob_sha1(source: bytes) -> str:
    payload = b"blob " + str(len(source)).encode("ascii") + b"\0" + source
    return hashlib.sha1(payload).hexdigest()


def _load_pinned_function(channel: str) -> Callable:
    if channel == "historical_proxy":
        filename, expected_blob, expected_sha256 = (
            "grading_pre_fix.py", PRE_FIX_BLOB, PRE_FIX_SHA256
        )
        function_names = {"get_eval_tests_report"}
    elif channel == "repaired_control":
        filename, expected_blob, expected_sha256 = (
            "grading_post_fix.py", POST_FIX_BLOB, POST_FIX_SHA256
        )
        function_names = {"test_passed", "test_failed", "get_eval_tests_report"}
    else:
        raise ValueError("unknown upstream grader channel")

    source = (FIXTURE_DIRECTORY / filename).read_bytes()
    if _git_blob_sha1(source) != expected_blob or hashlib.sha256(source).hexdigest() != expected_sha256:
        raise ValueError(f"pinned upstream source changed: {filename}")
    parsed = ast.parse(source, filename=filename)
    selected = [
        node for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name in function_names
    ]
    if {node.name for node in selected} != function_names:
        raise ValueError("pinned grader functions missing")

    namespace = {
        "TestStatus": _TestStatus,
        "FAIL_TO_PASS": FAIL_TO_PASS,
        "PASS_TO_PASS": PASS_TO_PASS,
        "FAIL_TO_FAIL": FAIL_TO_FAIL,
        "PASS_TO_FAIL": PASS_TO_FAIL,
    }
    executable = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(executable, filename, "exec"), namespace)
    return namespace["get_eval_tests_report"]


def _outcome(
    channel: str,
    observed_status_map: dict[str, str],
    gold_results: dict[str, list[str]],
) -> UpstreamGraderOutcome:
    grader = _load_pinned_function(channel)
    report = grader(observed_status_map, gold_results)
    f2p = report[FAIL_TO_PASS]
    p2p = report[PASS_TO_PASS]
    all_satisfied = (
        len(f2p["success"]) == len(gold_results[FAIL_TO_PASS])
        and len(p2p["success"]) == len(gold_results[PASS_TO_PASS])
        and not f2p["failure"]
        and not p2p["failure"]
    )
    return UpstreamGraderOutcome(
        source_commit=PRE_FIX_COMMIT if channel == "historical_proxy" else POST_FIX_COMMIT,
        source_blob=PRE_FIX_BLOB if channel == "historical_proxy" else POST_FIX_BLOB,
        channel=channel,
        verdict="PASS" if all_satisfied else "REJECT",
        f2p_success=f2p["success"],
        f2p_failure=f2p["failure"],
        p2p_success=p2p["success"],
        p2p_failure=p2p["failure"],
    )


def compare_missing_tests_case(case: str = "collection_failure") -> UpstreamGraderComparison:
    """Compare original and fixed graders on identical expected/observed tests."""

    gold_results = {
        FAIL_TO_PASS: ["tests/test_fix.py::test_regression"],
        PASS_TO_PASS: ["tests/test_keep.py::test_existing_behavior"],
    }
    if case == "collection_failure":
        observed_status_map: dict[str, str] = {}
        execution_health = "COLLECTION_FAILURE"
    elif case == "legitimate_solution":
        observed_status_map = {
            test: _TestStatus.PASSED.value
            for category in gold_results.values() for test in category
        }
        execution_health = "TESTS_EXECUTED"
    elif case == "ordinary_failure":
        observed_status_map = {
            test: _TestStatus.FAILED.value
            for category in gold_results.values() for test in category
        }
        execution_health = "TESTS_EXECUTED"
    else:
        raise ValueError("unknown checked-in SWE-Smith case")

    proxy = _outcome("historical_proxy", observed_status_map, gold_results)
    repaired = _outcome("repaired_control", observed_status_map, gold_results)
    if proxy.verdict == "PASS" and repaired.verdict == "REJECT":
        classification = "HISTORICAL_MISSING_TEST_FALSE_REWARD"
    elif proxy.verdict == repaired.verdict:
        classification = "AGREEMENT_" + proxy.verdict
    else:
        classification = "DISAGREEMENT"
    return UpstreamGraderComparison(
        case=case,
        expected_tests=[*gold_results[FAIL_TO_PASS], *gold_results[PASS_TO_PASS]],
        observed_status_map=observed_status_map,
        execution_health=execution_health,
        historical_proxy=proxy,
        repaired_control=repaired,
        classification=classification,
    )
