"""A local semantic review must never be mistaken for a production seal."""

import autoseal.promotion as promotion
from autoseal.evaluation import TestCounts as Counts, Verdict
from autoseal.promotion import review_local_repair
from autoseal.repair import RepairOperator, RepairPlan


def _plan(operator: RepairOperator, required_passes: int = 0) -> RepairPlan:
    return RepairPlan(
        operator=operator,
        allowed_files=("solution.py",) if operator is RepairOperator.ARTIFACT_PROJECTION else (),
        required_passes=required_passes,
    )


def test_local_projection_cannot_promote_when_termination_stress_is_unresolved() -> None:
    review = review_local_repair(_plan(RepairOperator.ARTIFACT_PROJECTION))
    gates = {gate.name: gate.passed for gate in review.gates}

    assert review.disposition == "REJECTED"
    assert review.seal_evidence is None
    assert len(review.controls) == 6
    assert all(gates[name] for name in (
        "frozen_corpus_identity", "complete_process_evidence", "baseline_oracle",
        "exploit_exclusion", "positive_preservation", "negative_preservation",
        "unaffected_native_parity", "heldout_reattack", "repeatable_verdicts",
    ))
    assert gates["provider_enforcement"] is False
    assert gates["privilege_and_rollback"] is False
    assert gates["early_termination_resistance"] is False
    assert review.termination_stress.proxy_verdict == "PASS"
    assert review.termination_stress.repaired_verdict == "INCONCLUSIVE"
    assert review.controls[-1].name == "exploit_holdout"
    assert review.controls[-1].repaired_verdict.value == "REJECT"


def test_overstrict_repair_is_rejected_even_when_it_blocks_exploit() -> None:
    review = review_local_repair(_plan(RepairOperator.VERDICT_OWNERSHIP, 8))
    gates = {gate.name: gate.passed for gate in review.gates}

    assert review.disposition == "REJECTED"
    assert gates["exploit_exclusion"] is True
    assert gates["positive_preservation"] is False
    assert review.seal_evidence is None


def test_unrelated_repair_cannot_claim_exploit_block() -> None:
    review = review_local_repair(_plan(RepairOperator.RESULT_BINDING))
    gates = {gate.name: gate.passed for gate in review.gates}

    assert review.disposition == "REJECTED"
    assert gates["exploit_exclusion"] is False
    assert gates["heldout_reattack"] is False
    assert review.seal_evidence is None


def test_verifier_failure_does_not_count_as_blocked_exploit(monkeypatch) -> None:
    original = promotion.apply_local_repair

    def broken(plan: RepairPlan, candidate: str):
        result = original(plan, candidate)
        if candidate == "exploit":
            return result.model_copy(update={"verdict": Verdict.VERIFIER_FAILURE})
        return result

    monkeypatch.setattr(promotion, "apply_local_repair", broken)
    review = review_local_repair(_plan(RepairOperator.ARTIFACT_PROJECTION))
    gates = {gate.name: gate.passed for gate in review.gates}

    assert review.disposition == "REJECTED"
    assert gates["complete_process_evidence"] is False
    assert gates["exploit_exclusion"] is False
    assert review.seal_evidence is None


def test_changed_repeat_counts_is_nondeterministic(monkeypatch) -> None:
    original = promotion.apply_local_repair
    seen: dict[str, int] = {}

    def flaky(plan: RepairPlan, candidate: str):
        result = original(plan, candidate)
        seen[candidate] = seen.get(candidate, 0) + 1
        if candidate == "exploit" and seen[candidate] == 2:
            return result.model_copy(update={"counts": Counts(passed=0, failed=4, skipped=0, errors=0)})
        return result

    monkeypatch.setattr(promotion, "apply_local_repair", flaky)
    review = review_local_repair(_plan(RepairOperator.ARTIFACT_PROJECTION))
    gates = {gate.name: gate.passed for gate in review.gates}

    assert review.disposition == "REJECTED"
    assert gates["repeatable_verdicts"] is False
    assert gates["early_termination_resistance"] is False
    assert review.seal_evidence is None
