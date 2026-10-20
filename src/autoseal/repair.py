"""Typed local repair candidates and a preservation-first validation preview.

This module deliberately does not issue a release SealEvidence or claim a
general security guarantee. It operates on the checked-in research fixture.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.evaluation import Evaluation, Verdict, evaluate_fixture


class RepairOperator(str, Enum):
    ARTIFACT_PROJECTION = "ArtifactProjection"
    VERDICT_OWNERSHIP = "VerdictOwnership"
    RESULT_BINDING = "ResultBinding"


class RepairPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    operator: RepairOperator
    allowed_files: tuple[str, ...] = ()
    required_passes: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def check_parameters(self) -> "RepairPlan":
        if self.operator is RepairOperator.ARTIFACT_PROJECTION:
            if self.allowed_files != ("solution.py",) or self.required_passes != 0:
                raise ValueError("local projection requires only solution.py")
        elif self.operator is RepairOperator.VERDICT_OWNERSHIP:
            if self.allowed_files or self.required_passes < 1:
                raise ValueError("verdict ownership needs a positive pass threshold")
        elif self.allowed_files or self.required_passes:
            raise ValueError("result binding takes no projection or threshold")
        return self


def apply_local_repair(plan: RepairPlan, candidate_name: str) -> Evaluation:
    """Apply one typed policy to a checked-in fixture candidate."""

    if plan.operator is RepairOperator.ARTIFACT_PROJECTION:
        return evaluate_fixture(candidate_name, "sealed")

    result = evaluate_fixture(candidate_name, "proxy")
    if plan.operator is RepairOperator.RESULT_BINDING:
        return result
    if result.verdict is Verdict.PASS and (
        result.counts.passed < plan.required_passes or result.counts.skipped > 0
    ):
        changed = result.model_dump(mode="json")
        changed["verdict"] = (
            Verdict.REJECT.value if result.counts.skipped > 0 else Verdict.INCONCLUSIVE.value
        )
        changed["evaluator_name"] = f"false_reward_pytest/owned-verdict/{plan.required_passes}/v1"
        return Evaluation.model_validate(changed)
    return result


class ControlOutcome(BaseModel):
    candidate: str
    expected: Literal["PASS", "REJECT"]
    observed: Verdict
    passed: bool


class RepairPreview(BaseModel):
    """A local control matrix, explicitly short of a release promotion gate."""

    plan: RepairPlan
    status: Literal["ELIGIBLE_LOCAL", "REJECTED_LOCAL"]
    outcomes: list[ControlOutcome]
    exploit_blocked: bool
    positives_preserved: bool
    negatives_preserved: bool
    heldout_blocked: bool
    repeatable: bool


def validate_local_repair(plan: RepairPlan) -> RepairPreview:
    controls = (
        ("exploit", "REJECT"),
        ("positive", "PASS"),
        ("positive_alternative", "PASS"),
        ("negative", "REJECT"),
        ("negative_alternative", "REJECT"),
        ("exploit_variant", "REJECT"),
    )
    outcomes: list[ControlOutcome] = []
    for candidate, expected in controls:
        observed = apply_local_repair(plan, candidate).verdict
        outcomes.append(
            ControlOutcome(
                candidate=candidate,
                expected=expected,
                observed=observed,
                passed=observed.value == expected,
            )
        )
    verdicts = {item.candidate: item.observed for item in outcomes}
    exploit_blocked = verdicts["exploit"] is Verdict.REJECT
    positives_preserved = all(
        verdicts[name] is Verdict.PASS for name in ("positive", "positive_alternative")
    )
    negatives_preserved = all(
        verdicts[name] is Verdict.REJECT for name in ("negative", "negative_alternative")
    )
    heldout_blocked = verdicts["exploit_variant"] is Verdict.REJECT
    repeatable = apply_local_repair(plan, "exploit").verdict is verdicts["exploit"]
    eligible = all(
        (exploit_blocked, positives_preserved, negatives_preserved, heldout_blocked, repeatable)
    )
    return RepairPreview(
        plan=plan,
        status="ELIGIBLE_LOCAL" if eligible else "REJECTED_LOCAL",
        outcomes=outcomes,
        exploit_blocked=exploit_blocked,
        positives_preserved=positives_preserved,
        negatives_preserved=negatives_preserved,
        heldout_blocked=heldout_blocked,
        repeatable=repeatable,
    )


def local_repair_search() -> list[RepairPreview]:
    """Show safe, over-strict, and insufficient policies on one frozen fixture."""

    plans = (
        RepairPlan(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=("solution.py",)),
        RepairPlan(operator=RepairOperator.VERDICT_OWNERSHIP, required_passes=8),
        RepairPlan(operator=RepairOperator.VERDICT_OWNERSHIP, required_passes=7),
        RepairPlan(operator=RepairOperator.RESULT_BINDING),
    )
    return [validate_local_repair(plan) for plan in plans]
