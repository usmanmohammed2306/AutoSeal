import pytest

from autoseal.experiment import Arm, ExperimentManifest, SeedRecord, compare_seed_records


def digest(character: str) -> str:
    return "sha256:" + character * 64


def manifest() -> ExperimentManifest:
    return ExperimentManifest(
        base_checkpoint=digest("a"), dataset_revision=digest("b"),
        task_pack_revision=digest("c"), prompt_revision=digest("d"),
        environment_revision=digest("e"), hidden_audit_revision=digest("f"),
        vulnerable_evaluator_revision=digest("1"), sealed_evaluator_revision=digest("2"),
        training_code_revision=digest("3"), seeds=(11, 22, 33), optimizer="adamw",
        learning_rate=1e-5, rollout_budget_per_seed=100, max_completion_tokens=256,
        stop_rule="100 rollouts", exclusion_rule="retain every failed seed",
    )


def records(config: ExperimentManifest) -> list[SeedRecord]:
    return [SeedRecord(
        manifest_id=digest("9"), arm=arm, seed=seed,
        reward_evaluator_revision=config.evaluator_for(arm),
        starting_checkpoint=config.base_checkpoint,
        dataset_revision=config.dataset_revision, prompt_revision=config.prompt_revision,
        rollout_count=100, audit_total=10, audit_success=7 if arm is Arm.SEALED else 6,
        false_rewards=1 if arm is Arm.SEALED else 3, gpu_seconds=45.0,
        checkpoint_id=digest("4"), evidence_id=digest("5"), status="COMPLETE",
    ) for arm in Arm for seed in config.seeds]


def test_frozen_manifest_and_seed_comparison() -> None:
    config = manifest()
    result = compare_seed_records(config, digest("9"), records(config))
    assert result.comparison_valid
    assert result.vulnerable.mean_false_reward == 0.3
    assert result.sealed.mean_false_reward == 0.1
    with pytest.raises(ValueError, match="missing arm or seed"):
        compare_seed_records(config, digest("9"), records(config)[:-1])


def test_incomparable_or_failed_seed_is_not_hidden() -> None:
    config = manifest()
    rows = records(config)
    rows[0] = rows[0].model_copy(update={"starting_checkpoint": digest("8")})
    with pytest.raises(ValueError, match="starting checkpoint"):
        compare_seed_records(config, digest("9"), rows)
    rows = records(config)
    rows[0] = rows[0].model_copy(update={
        "status": "FAILED", "failure_or_exclusion_reason": "worker lost",
        "audit_total": 0, "audit_success": 0, "false_rewards": 0,
    })
    comparison = compare_seed_records(config, digest("9"), rows)
    assert not comparison.comparison_valid
    assert len(comparison.excluded_or_failed) == 1


def test_audit_cannot_be_training_reward() -> None:
    config = manifest()
    with pytest.raises(ValueError, match="hidden audit"):
        ExperimentManifest.model_validate({
            **config.model_dump(), "hidden_audit_revision": config.sealed_evaluator_revision,
        })
    with pytest.raises(ValueError, match="unique and sorted"):
        ExperimentManifest.model_validate({**config.model_dump(), "seeds": (11, 11, 22)})
