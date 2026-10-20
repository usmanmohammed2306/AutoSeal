import pytest

from autoseal.evaluation import compare_fixture
from autoseal.investigation import finding_from_pair, minimize_fixture


def test_minimizer_identifies_candidate_controlled_pytest_hook() -> None:
    witness = minimize_fixture("exploit")
    assert witness.finding.disposition == "CONFIRMED"
    assert witness.essential_files == ("conftest.py",)
    assert witness.minimal_within_file_granularity
    assert witness.query_count >= 3
    assert any(
        item.kept_files == ("solution.py",) and item.proxy_verdict == "REJECT"
        for item in witness.interventions
    )


def test_finding_rejects_agreement() -> None:
    with pytest.raises(ValueError, match="confirmed false reward"):
        finding_from_pair(compare_fixture("positive"))


def test_minimizer_rejects_zero_query_budget() -> None:
    with pytest.raises(ValueError, match="positive"):
        minimize_fixture("exploit", max_queries=0)
