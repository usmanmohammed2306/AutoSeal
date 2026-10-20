"""Exercise the typed proxy and independent audit path."""

import pytest
from pydantic import ValidationError

from autoseal.evaluation import Evaluation, compare_fixture, evaluate_fixture


@pytest.mark.parametrize(
    ("candidate", "classification"),
    [
        ("positive", "AGREEMENT_PASS"),
        ("negative", "AGREEMENT_REJECT"),
        ("exploit", "FALSE_REWARD"),
        ("exploit_variant", "FALSE_REWARD"),
        ("exit_spoof", "INCONCLUSIVE"),
    ],
)
def test_proxy_audit_comparison(candidate: str, classification: str) -> None:
    result = compare_fixture(candidate)
    assert result.classification == classification
    assert result.proxy.candidate_identity == result.audit.candidate_identity


def test_sealed_channel_rejects_exploit() -> None:
    result = evaluate_fixture("exploit", "sealed")
    assert result.verdict == "REJECT"
    assert "conftest.py" not in result.copied_files


def test_early_termination_is_not_counted_as_repaired_rejection() -> None:
    proxy = evaluate_fixture("exit_spoof", "proxy")
    audit = evaluate_fixture("exit_spoof", "audit")
    sealed = evaluate_fixture("exit_spoof", "sealed")

    assert proxy.verdict == "PASS"
    assert proxy.counts.passed == 0
    assert audit.verdict == "INCONCLUSIVE"
    assert sealed.verdict == "INCONCLUSIVE"
    assert audit.candidate_identity == sealed.candidate_identity == proxy.candidate_identity


def test_identity_mismatch_fails_closed() -> None:
    pair = compare_fixture("exploit")
    other = compare_fixture("positive")
    with pytest.raises(ValidationError, match="identities differ"):
        pair.__class__.model_validate(
            {"proxy": pair.proxy.model_dump(), "audit": other.audit.model_dump(), "classification": "FALSE_REWARD"}
        )


def test_process_evidence_tampering_fails_closed() -> None:
    result = evaluate_fixture("positive", "proxy")
    tampered = result.model_dump()
    tampered["process"]["stdout"] = "fake pass"
    with pytest.raises(ValidationError, match="identity mismatch"):
        Evaluation.model_validate(tampered)


def test_unknown_fixture_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown checked-in fixture"):
        evaluate_fixture("../../tmp", "proxy")
