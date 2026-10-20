"""Typed proxy and audit decisions over one immutable candidate identity.

The fixture adapter executes checked-in examples on the host. It is not an
adversarial execution boundary. Future providers must use isolated workers.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.evidence import CommandEvidence, evidence_id
from autoseal.local_demo import ArtifactProjection, evaluate


class Verdict(str, Enum):
    PASS = "PASS"
    REJECT = "REJECT"
    INCONCLUSIVE = "INCONCLUSIVE"
    VERIFIER_FAILURE = "VERIFIER_FAILURE"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"


class TestCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    errors: int = Field(ge=0)


class Evaluation(BaseModel):
    """One channel's verdict, with provenance and process evidence bound."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    channel: Literal["proxy", "audit", "sealed"]
    candidate_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    solution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copied_files: list[str]
    counts: TestCounts
    verdict: Verdict
    process: CommandEvidence
    process_evidence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    evaluator_name: str

    @model_validator(mode="after")
    def check_verdict(self) -> "Evaluation":
        if self.process_evidence_id != evidence_id(self.process):
            raise ValueError("process evidence identity mismatch")
        if self.verdict is Verdict.PASS and self.process.status != "exited_zero":
            raise ValueError("a passing verifier must exit zero")
        if self.verdict is Verdict.REJECT and (
            self.process.status not in {"exited_zero", "exited_nonzero"}
            or self.counts.failed + self.counts.skipped == 0
        ):
            raise ValueError("candidate rejection requires failed or skipped tests")
        if self.process.status in {"launch_error", "timeout"} and self.verdict not in {
            Verdict.INFRASTRUCTURE_FAILURE,
            Verdict.VERIFIER_FAILURE,
        }:
            raise ValueError("launch and timeout cannot be candidate verdicts")
        return self


class PairedEvaluation(BaseModel):
    """A proxy and audit comparison that refuses identity mismatch."""

    model_config = ConfigDict(extra="forbid")

    proxy: Evaluation
    audit: Evaluation
    classification: Literal[
        "FALSE_REWARD", "AGREEMENT_PASS", "AGREEMENT_REJECT", "DISAGREEMENT", "INCONCLUSIVE"
    ]

    @model_validator(mode="after")
    def check_pair(self) -> "PairedEvaluation":
        if self.proxy.channel != "proxy" or self.audit.channel != "audit":
            raise ValueError("pair requires proxy and audit channels")
        if self.proxy.candidate_identity != self.audit.candidate_identity:
            raise ValueError("proxy and audit candidate identities differ")
        if self.proxy.verdict is Verdict.PASS and self.audit.verdict is Verdict.REJECT:
            expected = "FALSE_REWARD"
        elif self.proxy.verdict is Verdict.PASS and self.audit.verdict is Verdict.PASS:
            expected = "AGREEMENT_PASS"
        elif self.proxy.verdict is Verdict.REJECT and self.audit.verdict is Verdict.REJECT:
            expected = "AGREEMENT_REJECT"
        elif Verdict.INCONCLUSIVE in {self.proxy.verdict, self.audit.verdict} or any(
            verdict in {Verdict.VERIFIER_FAILURE, Verdict.INFRASTRUCTURE_FAILURE}
            for verdict in (self.proxy.verdict, self.audit.verdict)
        ):
            expected = "INCONCLUSIVE"
        else:
            expected = "DISAGREEMENT"
        if self.classification != expected:
            raise ValueError(f"classification must be {expected}")
        return self


def _typed_evaluation(raw: dict, evaluator_name: str) -> Evaluation:
    process = CommandEvidence.model_validate(raw["process"])
    if process.status == "launch_error":
        verdict = Verdict.INFRASTRUCTURE_FAILURE
    elif process.status == "timeout":
        verdict = Verdict.VERIFIER_FAILURE
    elif raw["verdict"] == "ERROR":
        verdict = Verdict.VERIFIER_FAILURE
    else:
        verdict = Verdict(raw["verdict"])
    return Evaluation(
        channel=raw["channel"],
        candidate_identity=raw["candidate_identity"],
        solution_sha256=raw["solution_sha256"],
        copied_files=raw["copied_files"],
        counts=TestCounts.model_validate(raw["counts"]),
        verdict=verdict,
        process=process,
        process_evidence_id=evidence_id(process),
        evaluator_name=evaluator_name,
    )


def evaluate_fixture(candidate_name: str, channel: str) -> Evaluation:
    """Evaluate only a named, checked-in local fixture."""

    if candidate_name not in {
        "positive", "positive_alternative", "negative", "negative_alternative",
        "exploit", "exploit_variant", "exploit_holdout", "exit_spoof",
    }:
        raise ValueError("unknown checked-in fixture")
    if channel not in {"proxy", "audit", "sealed"}:
        raise ValueError("unknown evaluator channel")
    raw = evaluate(candidate_name, channel=channel, projection=ArtifactProjection())
    return _typed_evaluation(raw, f"false_reward_pytest/{channel}/v1")


def compare_fixture(candidate_name: str) -> PairedEvaluation:
    proxy = evaluate_fixture(candidate_name, "proxy")
    audit = evaluate_fixture(candidate_name, "audit")
    if proxy.verdict is Verdict.PASS and audit.verdict is Verdict.REJECT:
        classification = "FALSE_REWARD"
    elif proxy.verdict is Verdict.PASS and audit.verdict is Verdict.PASS:
        classification = "AGREEMENT_PASS"
    elif proxy.verdict is Verdict.REJECT and audit.verdict is Verdict.REJECT:
        classification = "AGREEMENT_REJECT"
    elif any(
        verdict in {Verdict.INCONCLUSIVE, Verdict.VERIFIER_FAILURE, Verdict.INFRASTRUCTURE_FAILURE}
        for verdict in (proxy.verdict, audit.verdict)
    ):
        classification = "INCONCLUSIVE"
    else:
        classification = "DISAGREEMENT"
    return PairedEvaluation(proxy=proxy, audit=audit, classification=classification)
