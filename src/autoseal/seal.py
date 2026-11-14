"""Typed repair evidence and a closed adapter registry for admission.

Evidence binds a bounded empirical claim. It is not a third-party certificate
or a guarantee against every possible exploit. Trusted host/CAS is assumed.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from autoseal.storage import ContentAddressedStore, IntegrityError


DIGEST = r"^sha256:[0-9a-f]{64}$"


class SealEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    kind: Literal["seal_evidence"] = "seal_evidence"
    adapter: Literal["artifact_output_v1"]
    parent_revision: str = Field(pattern=DIGEST)
    child_revision: str = Field(pattern=DIGEST)
    case_identity: str = Field(pattern=DIGEST)
    dataset_revision: str = Field(pattern=DIGEST)
    checkpoint_revision: Optional[str] = Field(default=None, pattern=DIGEST)
    plan_identity: str = Field(pattern=DIGEST)
    validation_identity: str = Field(pattern=DIGEST)
    provider_identity: str = Field(pattern=DIGEST)
    image_identity: str = Field(pattern=DIGEST)
    verify_command: tuple[str, ...]
    rollback_command: tuple[str, ...]
    assumptions: tuple[str, ...] = Field(min_length=1)
    expiration_conditions: tuple[str, ...] = Field(min_length=1)


def verify_seal(store: ContentAddressedStore, identity: str, *, child_revision: str) -> SealEvidence:
    seal = SealEvidence.model_validate(store.get_json(identity))
    if seal.child_revision != child_revision:
        raise IntegrityError("SealEvidence belongs to another child revision")
    if seal.adapter == "artifact_output_v1":
        from autoseal.artifact_pipeline import verify_artifact_validation
        checked = verify_artifact_validation(store, seal.validation_identity)
        expected = {"parent_revision": checked["parent_revision"], "child_revision": checked["child_revision"],
            "case_identity": checked["case_id"], "dataset_revision": checked["case_id"],
            "plan_identity": checked["plan_id"], "provider_identity": checked["provider_id"],
            "image_identity": checked["image"]}
        if not all(checked["gates"].values()) or any(getattr(seal, key) != value for key, value in expected.items()):
            raise IntegrityError("SealEvidence does not match a fully verified validation")
    return seal
