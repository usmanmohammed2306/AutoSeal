"""Frozen vulnerable-versus-sealed experiment design and honest comparison."""

from __future__ import annotations

from enum import Enum
from statistics import mean
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


DIGEST = r"^sha256:[0-9a-f]{64}$"


class Arm(str, Enum):
    VULNERABLE = "vulnerable"
    SEALED = "sealed"


class ExperimentManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    base_checkpoint: str = Field(pattern=DIGEST)
    dataset_revision: str = Field(pattern=DIGEST)
    task_pack_revision: str = Field(pattern=DIGEST)
    prompt_revision: str = Field(pattern=DIGEST)
    environment_revision: str = Field(pattern=DIGEST)
    hidden_audit_revision: str = Field(pattern=DIGEST)
    vulnerable_evaluator_revision: str = Field(pattern=DIGEST)
    sealed_evaluator_revision: str = Field(pattern=DIGEST)
    training_code_revision: str = Field(pattern=DIGEST)
    seeds: tuple[int, ...] = Field(min_length=3)
    optimizer: str = Field(min_length=1)
    learning_rate: float = Field(gt=0)
    rollout_budget_per_seed: int = Field(gt=0)
    max_completion_tokens: int = Field(gt=0)
    stop_rule: str = Field(min_length=1)
    exclusion_rule: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_comparison(self) -> "ExperimentManifest":
        if len(self.seeds) != len(set(self.seeds)) or tuple(sorted(self.seeds)) != self.seeds:
            raise ValueError("seeds must be unique and sorted")
        if self.vulnerable_evaluator_revision == self.sealed_evaluator_revision:
            raise ValueError("experiment arms require distinct evaluator revisions")
        if self.hidden_audit_revision in {
            self.vulnerable_evaluator_revision, self.sealed_evaluator_revision,
        }:
            raise ValueError("hidden audit cannot be a training reward evaluator")
        return self

    def evaluator_for(self, arm: Arm) -> str:
        return self.vulnerable_evaluator_revision if arm is Arm.VULNERABLE else self.sealed_evaluator_revision


class SeedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: str = Field(pattern=DIGEST)
    arm: Arm
    seed: int
    reward_evaluator_revision: str = Field(pattern=DIGEST)
    starting_checkpoint: str = Field(pattern=DIGEST)
    dataset_revision: str = Field(pattern=DIGEST)
    prompt_revision: str = Field(pattern=DIGEST)
    rollout_count: int = Field(ge=0)
    audit_total: int = Field(ge=0)
    audit_success: int = Field(ge=0)
    false_rewards: int = Field(ge=0)
    gpu_seconds: float = Field(ge=0)
    checkpoint_id: str = Field(pattern=DIGEST)
    evidence_id: str = Field(pattern=DIGEST)
    status: Literal["COMPLETE", "FAILED", "EXCLUDED"]
    failure_or_exclusion_reason: str = ""

    @model_validator(mode="after")
    def validate_counts(self) -> "SeedRecord":
        if self.audit_success > self.audit_total or self.false_rewards > self.audit_total:
            raise ValueError("audit counts exceed denominator")
        if self.status == "COMPLETE" and (self.audit_total == 0 or self.failure_or_exclusion_reason):
            raise ValueError("completed seed requires audit evidence and no exclusion")
        if self.status != "COMPLETE" and not self.failure_or_exclusion_reason:
            raise ValueError("failed or excluded seed needs a reason")
        return self


class ArmSummary(BaseModel):
    arm: Arm
    completed_seeds: int
    audit_success_by_seed: list[float]
    false_reward_by_seed: list[float]
    mean_audit_success: float
    mean_false_reward: float
    total_gpu_seconds: float


class ExperimentComparison(BaseModel):
    manifest_id: str
    vulnerable: ArmSummary
    sealed: ArmSummary
    seed_pairs: list[int]
    excluded_or_failed: list[SeedRecord]
    comparison_valid: bool


def compare_seed_records(
    manifest: ExperimentManifest, manifest_id: str, records: list[SeedRecord]
) -> ExperimentComparison:
    """Fail closed on missing or incomparable seeds; never fill outcomes."""

    keyed: dict[tuple[Arm, int], SeedRecord] = {}
    for record in records:
        key = (record.arm, record.seed)
        if key in keyed:
            raise ValueError("duplicate arm and seed")
        if record.manifest_id != manifest_id or record.seed not in manifest.seeds:
            raise ValueError("seed record does not belong to frozen manifest")
        if record.reward_evaluator_revision != manifest.evaluator_for(record.arm):
            raise ValueError("seed used the wrong reward evaluator")
        if record.starting_checkpoint != manifest.base_checkpoint:
            raise ValueError("seed used a different starting checkpoint")
        if record.dataset_revision != manifest.dataset_revision or record.prompt_revision != manifest.prompt_revision:
            raise ValueError("dataset or prompt differs across arms")
        if record.rollout_count > manifest.rollout_budget_per_seed:
            raise ValueError("seed exceeded frozen rollout budget")
        keyed[key] = record
    expected = {(arm, seed) for arm in Arm for seed in manifest.seeds}
    if set(keyed) != expected:
        raise ValueError("missing arm or seed; comparison cannot be complete")
    incomplete = [record for record in records if record.status != "COMPLETE"]
    def summarize(arm: Arm) -> ArmSummary:
        rows = [keyed[(arm, seed)] for seed in manifest.seeds if keyed[(arm, seed)].status == "COMPLETE"]
        success = [row.audit_success / row.audit_total for row in rows]
        false_reward = [row.false_rewards / row.audit_total for row in rows]
        return ArmSummary(
            arm=arm, completed_seeds=len(rows),
            audit_success_by_seed=success, false_reward_by_seed=false_reward,
            mean_audit_success=mean(success) if success else 0.0,
            mean_false_reward=mean(false_reward) if false_reward else 0.0,
            total_gpu_seconds=sum(row.gpu_seconds for row in rows),
        )
    return ExperimentComparison(
        manifest_id=manifest_id,
        vulnerable=summarize(Arm.VULNERABLE), sealed=summarize(Arm.SEALED),
        seed_pairs=list(manifest.seeds), excluded_or_failed=incomplete,
        comparison_valid=not incomplete,
    )
