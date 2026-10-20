"""Exercise the public SWE-bench xfail mechanism with its pinned native grader."""

import json

import pytest

from autoseal.cli import main
from autoseal.upstream_swebench import (
    _native_functions,
    compare_swebench_case,
    preview_swebench_f2p_repair,
)


def test_candidate_controlled_xfail_earns_false_reward_without_fixing_solution() -> None:
    case = compare_swebench_case("xfail")
    assert case.classification == "FALSE_REWARD"
    assert case.proxy.process.exit_code == 0
    assert case.proxy.observed_status_map["test_contract.py::test_regression"] == "XFAIL"
    assert "[NOTRUN]" in case.proxy.process.stdout
    assert case.proxy.grader_resolution == "RESOLVED_FULL"
    assert case.proxy.verdict == "PASS"
    assert case.audit.observed_status_map["test_contract.py::test_regression"] == "FAILED"
    assert case.audit.grader_resolution == "RESOLVED_NO"
    assert case.audit.verdict == "REJECT"
    assert "conftest.py" in case.proxy.copied_files
    assert "conftest.py" not in case.audit.copied_files


@pytest.mark.parametrize(
    ("name", "classification"),
    [("clean", "AGREEMENT_REJECT"), ("skip", "AGREEMENT_REJECT"), ("positive", "AGREEMENT_PASS")],
)
def test_upstream_controls(name: str, classification: str) -> None:
    case = compare_swebench_case(name)
    assert case.classification == classification
    assert case.proxy.verdict == case.audit.verdict
    if name != "positive":
        assert case.solution_sha256 == compare_swebench_case("xfail").solution_sha256


def test_pinned_upstream_code_is_integrity_checked(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor/grading.py").write_text("def test_passed(): return True\n")
    monkeypatch.setattr("autoseal.upstream_swebench.CASE_ROOT", tmp_path)
    with pytest.raises(ValueError, match="pinned SWE-bench source changed"):
        _native_functions()


def test_swebench_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["upstream-swebench", "xfail"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["classification"] == "FALSE_REWARD"
    assert report["proxy"]["grader_resolution"] == "RESOLVED_FULL"


def test_scoped_repair_blocks_xfail_without_breaking_p2p_xfail() -> None:
    preview = preview_swebench_f2p_repair()
    assert preview.disposition == "ELIGIBLE_LOCAL"
    rows = {row.case: row for row in preview.controls}
    assert rows["xfail"].proxy_verdict == "PASS"
    assert rows["xfail"].repaired_verdict == "REJECT"
    assert rows["xfail_variant"].repaired_verdict == "REJECT"
    assert rows["positive"].repaired_verdict == "PASS"
    assert rows["p2p_xfail"].repaired_verdict == "PASS"
    assert all(row.preserved for row in preview.controls)
    assert "no upstream patch" in preview.limitation
