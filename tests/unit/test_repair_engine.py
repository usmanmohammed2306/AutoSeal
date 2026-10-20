import pytest
from pydantic import ValidationError

from autoseal.repair import RepairOperator
from autoseal.repair_engine import (
    REQUIRED_BINDINGS,
    AdvertisedCapabilities,
    PolicyOverlay,
    PrivilegeSurface,
    ProviderPrimitive,
    TypedRepairPlan,
    TypedRepairStep,
    VerifierPolicy,
    apply_typed_plan,
    rollback_policy,
)


def _parent() -> VerifierPolicy:
    return VerifierPolicy(
        candidate_files=("conftest.py", "solution.py", "src/helper.py"),
        verdict_owner="candidate_workspace",
        privileges=PrivilegeSurface(
            reads=("candidate", "verifier"), writes=("reward",),
            network=("none",), secrets=(), capabilities=(),
        ),
    )


def _steps() -> tuple[TypedRepairStep, ...]:
    return (
        TypedRepairStep(
            operator=RepairOperator.ARTIFACT_PROJECTION,
            allowed_files=("solution.py", "src/helper.py"),
        ),
        TypedRepairStep(operator=RepairOperator.VERDICT_OWNERSHIP),
        TypedRepairStep(
            operator=RepairOperator.RESULT_BINDING,
            required_bindings=REQUIRED_BINDINGS,
        ),
    )


def _capabilities(*primitives: ProviderPrimitive) -> AdvertisedCapabilities:
    return AdvertisedCapabilities(primitives=primitives)


def test_composed_plan_is_deterministic_and_rolls_back_exact_policy() -> None:
    parent = _parent()
    plan = TypedRepairPlan(parent_policy_identity=parent.identity, steps=_steps())
    capabilities = _capabilities(*ProviderPrimitive)

    applied = apply_typed_plan(parent, plan, capabilities)
    repeated = apply_typed_plan(parent, plan, capabilities)

    assert plan.identity == TypedRepairPlan.model_validate(plan.model_dump()).identity
    assert applied.child_policy_identity == repeated.child_policy_identity
    assert applied.plan_identity == plan.identity
    assert applied.child.candidate_files == ("solution.py", "src/helper.py")
    assert applied.child.verdict_owner == "trusted_verifier"
    assert "reward" not in applied.child.privileges.writes
    assert applied.child.result_bindings == REQUIRED_BINDINGS
    assert [overlay.operator for overlay in applied.forward_overlays] == list(RepairOperator)
    assert [overlay.operator for overlay in applied.inverse_overlays] == list(reversed(RepairOperator))
    assert rollback_policy(applied, applied.child) == parent


def test_missing_capability_and_parent_mismatch_fail_before_application() -> None:
    parent = _parent()
    plan = TypedRepairPlan(parent_policy_identity=parent.identity, steps=_steps())

    with pytest.raises(ValueError, match="trusted_verdict_owner"):
        apply_typed_plan(parent, plan, _capabilities(ProviderPrimitive.ARTIFACT_PROJECTION))
    different = VerifierPolicy(candidate_files=("solution.py",), verdict_owner="candidate_workspace")
    with pytest.raises(ValueError, match="different parent"):
        apply_typed_plan(different, plan, _capabilities(*ProviderPrimitive))


def test_conflicting_or_wrongly_ordered_steps_fail() -> None:
    parent = _parent()
    projection = _steps()[0]
    with pytest.raises(ValidationError, match="only once"):
        TypedRepairPlan(parent_policy_identity=parent.identity, steps=(projection, projection))
    with pytest.raises(ValidationError, match="canonical"):
        TypedRepairPlan(parent_policy_identity=parent.identity, steps=tuple(reversed(_steps())))
    binding_only = TypedRepairPlan(parent_policy_identity=parent.identity, steps=(_steps()[2],))
    with pytest.raises(ValueError, match="trusted verdict owner"):
        apply_typed_plan(parent, binding_only, _capabilities(*ProviderPrimitive))


@pytest.mark.parametrize("path", ("../solution.py", "/solution.py", "src/../solution.py", "src//helper.py", "C:/secret", "src\\helper.py", "a/./b"))
def test_projection_rejects_unsafe_or_noncanonical_paths(path: str) -> None:
    with pytest.raises(ValidationError, match="relative paths"):
        TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=(path,))


def test_projection_must_narrow_without_losing_required_source() -> None:
    parent = _parent()
    same = TypedRepairPlan(
        parent_policy_identity=parent.identity,
        steps=(TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=parent.candidate_files),),
    )
    with pytest.raises(ValueError, match="strictly narrow"):
        apply_typed_plan(parent, same, _capabilities(ProviderPrimitive.ARTIFACT_PROJECTION))
    extra = TypedRepairPlan(
        parent_policy_identity=parent.identity,
        steps=(TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=("solution.py", "unapproved.py")),),
    )
    with pytest.raises(ValueError, match="strictly narrow"):
        apply_typed_plan(parent, extra, _capabilities(ProviderPrimitive.ARTIFACT_PROJECTION))


def test_policy_drift_prevents_rollback_and_privilege_growth_is_rejected() -> None:
    parent = _parent()
    plan = TypedRepairPlan(parent_policy_identity=parent.identity, steps=(_steps()[0],))
    applied = apply_typed_plan(parent, plan, _capabilities(ProviderPrimitive.ARTIFACT_PROJECTION))
    drifted = applied.child.model_copy(update={"candidate_files": ("solution.py",)})
    with pytest.raises(ValueError, match="drift"):
        rollback_policy(applied, drifted)

    broader = parent.model_copy(update={
        "privileges": PrivilegeSurface(
            reads=("candidate", "verifier"), writes=("reward",),
            network=("internet", "none"),
        ),
    })
    with pytest.raises(ValidationError, match="broadened"):
        PolicyOverlay(
            operator=RepairOperator.VERDICT_OWNERSHIP,
            direction="forward",
            before_identity=parent.identity, after_identity=broader.identity,
            before=parent, after=broader,
        )
