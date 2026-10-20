"""Typed, reversible verifier-policy overlays.

This module validates *declared* policy changes. It does not prove that a
provider enforces them. Production promotion still requires active probes,
native parity, hostile-code isolation, and managed-artifact rollback.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.repair import RepairOperator
from autoseal.projection import safe_relative_artifact_path


REQUIRED_BINDINGS = ("task", "candidate", "verifier", "policy", "provider", "environment")


def _digest(domain: bytes, model: BaseModel) -> str:
    payload = json.dumps(
        model.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain + payload).hexdigest()


class ProviderPrimitive(str, Enum):
    ARTIFACT_PROJECTION = "artifact_projection"
    TRUSTED_VERDICT_OWNER = "trusted_verdict_owner"
    RESULT_IDENTITY_BINDING = "result_identity_binding"


class AdvertisedCapabilities(BaseModel):
    """Design-time declaration only; a runtime probe must confirm each item."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    primitives: tuple[ProviderPrimitive, ...] = ()

    @model_validator(mode="after")
    def unique_primitives(self) -> "AdvertisedCapabilities":
        if len(self.primitives) != len(set(self.primitives)):
            raise ValueError("duplicate provider primitive")
        return self


class PrivilegeSurface(BaseModel):
    """Declared rights; runtime privilege measurement is a separate gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()
    network: tuple[str, ...] = ()
    secrets: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()

    @model_validator(mode="after")
    def canonical(self) -> "PrivilegeSurface":
        for field in ("reads", "writes", "network", "secrets", "capabilities"):
            values = getattr(self, field)
            if any(not value for value in values) or tuple(sorted(set(values))) != values:
                raise ValueError(f"{field} must contain unique sorted nonempty values")
        return self

    def no_broader_than(self, other: "PrivilegeSurface") -> bool:
        return all(
            set(getattr(self, field)) <= set(getattr(other, field))
            for field in ("reads", "writes", "network", "secrets", "capabilities")
        )


class VerifierPolicy(BaseModel):
    """Serializable policy state to which typed repair operators apply."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    candidate_files: tuple[str, ...] = Field(min_length=1)
    verdict_owner: Literal["candidate_workspace", "trusted_verifier"]
    result_bindings: tuple[str, ...] = ()
    privileges: PrivilegeSurface = Field(default_factory=PrivilegeSurface)

    @model_validator(mode="after")
    def canonical(self) -> "VerifierPolicy":
        if any(not safe_relative_artifact_path(path) for path in self.candidate_files):
            raise ValueError("candidate files must be canonical relative paths")
        if tuple(sorted(set(self.candidate_files))) != self.candidate_files:
            raise ValueError("candidate files must be unique and sorted")
        if self.result_bindings and self.result_bindings != REQUIRED_BINDINGS:
            raise ValueError("result binding must include all required identities in canonical order")
        return self

    @property
    def identity(self) -> str:
        return _digest(b"autoseal.verifier-policy.v1\0", self)


class TypedRepairStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: RepairOperator
    allowed_files: tuple[str, ...] = ()
    required_bindings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_parameters(self) -> "TypedRepairStep":
        if self.operator is RepairOperator.ARTIFACT_PROJECTION:
            if not self.allowed_files or self.required_bindings:
                raise ValueError("projection requires an allowlist and no binding fields")
            if any(not safe_relative_artifact_path(path) for path in self.allowed_files):
                raise ValueError("projection requires canonical relative paths")
            if tuple(sorted(set(self.allowed_files))) != self.allowed_files:
                raise ValueError("projection allowlist must be unique and sorted")
        elif self.operator is RepairOperator.VERDICT_OWNERSHIP:
            if self.allowed_files or self.required_bindings:
                raise ValueError("verdict ownership takes no file or binding parameters")
        elif self.allowed_files or self.required_bindings != REQUIRED_BINDINGS:
            raise ValueError("result binding requires every canonical identity field")
        return self

    @property
    def required_primitive(self) -> ProviderPrimitive:
        return {
            RepairOperator.ARTIFACT_PROJECTION: ProviderPrimitive.ARTIFACT_PROJECTION,
            RepairOperator.VERDICT_OWNERSHIP: ProviderPrimitive.TRUSTED_VERDICT_OWNER,
            RepairOperator.RESULT_BINDING: ProviderPrimitive.RESULT_IDENTITY_BINDING,
        }[self.operator]


class TypedRepairPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    parent_policy_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    steps: tuple[TypedRepairStep, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def no_conflicts(self) -> "TypedRepairPlan":
        operators = [step.operator for step in self.steps]
        if len(operators) != len(set(operators)):
            raise ValueError("a typed operator may appear only once in a plan")
        order = list(RepairOperator)
        if operators != sorted(operators, key=order.index):
            raise ValueError("operators must use canonical projection, ownership, binding order")
        return self

    @property
    def identity(self) -> str:
        return _digest(b"autoseal.typed-repair-plan.v1\0", self)


class PolicyOverlay(BaseModel):
    """Exact before/after policy snapshots for one typed operator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operator: RepairOperator
    direction: Literal["forward", "inverse"]
    before_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    after_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    before: VerifierPolicy
    after: VerifierPolicy

    @model_validator(mode="after")
    def validate_identities(self) -> "PolicyOverlay":
        if self.before.identity != self.before_identity or self.after.identity != self.after_identity:
            raise ValueError("overlay policy identity mismatch")
        if self.before_identity == self.after_identity:
            raise ValueError("no-op overlay is not a repair")
        if self.direction == "forward" and not self.after.privileges.no_broader_than(self.before.privileges):
            raise ValueError("repair broadened declared privileges")
        return self


class AppliedRepairPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    parent_policy_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    child_policy_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    forward_overlays: tuple[PolicyOverlay, ...]
    inverse_overlays: tuple[PolicyOverlay, ...]
    child: VerifierPolicy

    @model_validator(mode="after")
    def complete_chain(self) -> "AppliedRepairPlan":
        if not self.forward_overlays or len(self.forward_overlays) != len(self.inverse_overlays):
            raise ValueError("incomplete forward or inverse overlay chain")
        current = self.parent_policy_identity
        for overlay in self.forward_overlays:
            if overlay.direction != "forward":
                raise ValueError("forward chain contains an inverse overlay")
            if overlay.before_identity != current:
                raise ValueError("forward overlay chain is broken")
            current = overlay.after_identity
        if current != self.child_policy_identity or self.child.identity != current:
            raise ValueError("child policy identity mismatch")
        for overlay in self.inverse_overlays:
            if overlay.direction != "inverse":
                raise ValueError("inverse chain contains a forward overlay")
            if overlay.before_identity != current:
                raise ValueError("inverse overlay chain is broken")
            current = overlay.after_identity
        if current != self.parent_policy_identity:
            raise ValueError("inverse does not restore the parent policy")
        return self


def apply_typed_plan(
    parent: VerifierPolicy, plan: TypedRepairPlan, capabilities: AdvertisedCapabilities,
) -> AppliedRepairPlan:
    """Apply only narrowing policy transitions with advertised primitives.

    Advertisements satisfy design-time preconditions only. They cannot be
    substituted for runtime enforcement evidence in promotion.
    """

    if parent.identity != plan.parent_policy_identity:
        raise ValueError("plan is bound to a different parent policy")
    current = parent
    forward: list[PolicyOverlay] = []
    for step in plan.steps:
        if step.required_primitive not in capabilities.primitives:
            raise ValueError(f"provider does not advertise {step.required_primitive.value}")
        if step.operator is RepairOperator.ARTIFACT_PROJECTION:
            if not set(step.allowed_files) < set(current.candidate_files):
                raise ValueError("projection must strictly narrow existing candidate files")
            changed = current.model_copy(update={"candidate_files": step.allowed_files})
        elif step.operator is RepairOperator.VERDICT_OWNERSHIP:
            if current.verdict_owner != "candidate_workspace":
                raise ValueError("trusted verdict ownership is already in effect")
            reduced_privileges = current.privileges.model_copy(update={
                "writes": tuple(item for item in current.privileges.writes if item != "reward"),
            })
            changed = current.model_copy(update={
                "verdict_owner": "trusted_verifier", "privileges": reduced_privileges,
            })
        else:
            if current.verdict_owner != "trusted_verifier":
                raise ValueError("result binding requires a trusted verdict owner first")
            if "reward" in current.privileges.writes:
                raise ValueError("candidate still has reward write privilege")
            if current.result_bindings:
                raise ValueError("result binding is already in effect")
            changed = current.model_copy(update={"result_bindings": step.required_bindings})
        changed = VerifierPolicy.model_validate(changed.model_dump(mode="json"))
        forward.append(PolicyOverlay(
            operator=step.operator, direction="forward",
            before_identity=current.identity, after_identity=changed.identity,
            before=current, after=changed,
        ))
        current = changed
    inverse = tuple(
        PolicyOverlay(
            operator=overlay.operator,
            direction="inverse",
            before_identity=overlay.after_identity,
            after_identity=overlay.before_identity,
            before=overlay.after,
            after=overlay.before,
        )
        for overlay in reversed(forward)
    )
    return AppliedRepairPlan(
        plan_identity=plan.identity,
        parent_policy_identity=parent.identity,
        child_policy_identity=current.identity,
        forward_overlays=tuple(forward), inverse_overlays=inverse, child=current,
    )


def rollback_policy(applied: AppliedRepairPlan, observed_child: VerifierPolicy) -> VerifierPolicy:
    """Restore the exact policy parent only if the observed child is unchanged."""

    if observed_child.identity != applied.child_policy_identity:
        raise ValueError("child policy drift prevents exact rollback")
    current = observed_child
    for overlay in applied.inverse_overlays:
        if current.identity != overlay.before_identity:
            raise ValueError("inverse precondition failed")
        current = overlay.after
    if current.identity != applied.parent_policy_identity:
        raise ValueError("rollback did not restore the exact parent identity")
    return current


def local_composed_policy_preview() -> dict:
    """Demonstrate the complete typed grammar without claiming enforcement."""

    parent = VerifierPolicy(
        candidate_files=("conftest.py", "solution.py"),
        verdict_owner="candidate_workspace",
        privileges=PrivilegeSurface(
            reads=("candidate", "verifier"), writes=("reward",), network=("none",),
        ),
    )
    plan = TypedRepairPlan(
        parent_policy_identity=parent.identity,
        steps=(
            TypedRepairStep(
                operator=RepairOperator.ARTIFACT_PROJECTION,
                allowed_files=("solution.py",),
            ),
            TypedRepairStep(operator=RepairOperator.VERDICT_OWNERSHIP),
            TypedRepairStep(
                operator=RepairOperator.RESULT_BINDING,
                required_bindings=REQUIRED_BINDINGS,
            ),
        ),
    )
    advertised = AdvertisedCapabilities(primitives=tuple(ProviderPrimitive))
    applied = apply_typed_plan(parent, plan, advertised)
    restored = rollback_policy(applied, applied.child)
    return {
        "scope": "design-time policy overlay only; provider enforcement and managed-artifact rollback unproven",
        "plan_identity": plan.identity,
        "parent_policy_identity": parent.identity,
        "child_policy_identity": applied.child_policy_identity,
        "forward_operators": [overlay.operator.value for overlay in applied.forward_overlays],
        "inverse_operators": [overlay.operator.value for overlay in applied.inverse_overlays],
        "policy_rollback_exact": restored.identity == parent.identity,
        "provider_capability_proven": False,
        "managed_artifact_rollback_proven": False,
        "seal_evidence": None,
    }
