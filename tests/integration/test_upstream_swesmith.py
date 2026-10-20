"""Regression evidence from the actual pre-fix and post-fix SWE-Smith grader."""

import json

import pytest

from autoseal.cli import main
from autoseal.upstream_swesmith import (
    FIXTURE_DIRECTORY,
    _load_pinned_function,
    compare_missing_tests_case,
)


def test_historical_grader_awards_missing_tests_and_fix_rejects_them() -> None:
    comparison = compare_missing_tests_case("collection_failure")

    assert comparison.execution_health == "COLLECTION_FAILURE"
    assert comparison.observed_status_map == {}
    assert comparison.historical_proxy.verdict == "PASS"
    assert comparison.historical_proxy.f2p_success == [comparison.expected_tests[0]]
    assert comparison.historical_proxy.p2p_success == [comparison.expected_tests[1]]
    assert comparison.repaired_control.verdict == "REJECT"
    assert comparison.repaired_control.f2p_failure == [comparison.expected_tests[0]]
    assert comparison.repaired_control.p2p_failure == [comparison.expected_tests[1]]
    assert comparison.classification == "HISTORICAL_MISSING_TEST_FALSE_REWARD"


@pytest.mark.parametrize(
    ("case", "expected"),
    [("legitimate_solution", "PASS"), ("ordinary_failure", "REJECT")],
)
def test_upstream_fix_preserves_controls(case: str, expected: str) -> None:
    comparison = compare_missing_tests_case(case)
    assert comparison.historical_proxy.verdict == expected
    assert comparison.repaired_control.verdict == expected
    assert comparison.classification == "AGREEMENT_" + expected


def test_pinned_source_mismatch_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    (tmp_path / "grading_pre_fix.py").write_text("def get_eval_tests_report(): pass\n")
    monkeypatch.setattr("autoseal.upstream_swesmith.FIXTURE_DIRECTORY", tmp_path)
    with pytest.raises(ValueError, match="pinned upstream source changed"):
        _load_pinned_function("historical_proxy")
    assert (FIXTURE_DIRECTORY / "LICENSE").is_file()


def test_upstream_cli_exposes_source_identity(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["upstream-swesmith", "collection_failure"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["historical_proxy"]["verdict"] == "PASS"
    assert output["repaired_control"]["verdict"] == "REJECT"
    assert output["historical_proxy"]["source_blob"] == "0e66033191a1127091f26a0e2e83c6539c7606a0"
