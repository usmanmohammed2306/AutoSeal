"""Reviewed trajectory conversion and immutable dataset split commitments."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.trajectory import load_trajectory


class Split(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    AUDIT = "audit"
    HELDOUT = "heldout"


class ReviewDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class TrajectoryReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    trajectory_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    reviewer: str = Field(min_length=1)
    decision: ReviewDecision
    reason: str = Field(min_length=10)
    source_audit_verdict: Literal["PASS", "REJECT", "INCONCLUSIVE", "VERIFIER_FAILURE", "INFRASTRUCTURE_FAILURE"]


class SFTExample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    source_trajectory_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    review_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    task_id: str
    prompt: str
    completion: str


def reviewed_sft_example(
    store: ContentAddressedStore, review: TrajectoryReview, *, prompt: str
) -> SFTExample:
    """Convert only a reviewed, audit-passing scripted trajectory.

    The completion contains the candidate artifact alone. Audit details are
    used for eligibility but never copied into model-visible text.
    """

    if review.decision is not ReviewDecision.ACCEPT:
        raise ValueError("rejected trajectory cannot become SFT data")
    if review.source_audit_verdict != "PASS":
        raise ValueError("SFT source must pass the independent audit")
    if not prompt.strip():
        raise ValueError("SFT prompt must not be empty")
    record = load_trajectory(store, review.trajectory_id)
    if not record.complete_evidence:
        raise ValueError("incomplete trajectory cannot become SFT data")
    results = [store.get_json(event.object_id) for event in record.events if event.kind == "evaluation"]
    if results[1]["verdict"] != review.source_audit_verdict:
        raise IntegrityError("review audit verdict does not match stored evidence")
    artifact_event = next(event for event in record.events if event.kind == "artifact")
    artifact = store.get_json(artifact_event.object_id)
    if artifact["name"] != "solution.py":
        raise ValueError("unsupported training artifact")
    completion = store.get_bytes(artifact["content_id"]).decode("utf-8")
    review_id = store.put_json(review.model_dump(mode="json"))
    return SFTExample(
        source_trajectory_id=review.trajectory_id,
        review_id=review_id,
        task_id="fixture/is_even/v1",
        prompt=prompt,
        completion=completion,
    )


class DatasetItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1)
    content_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    source_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    split: Split


class DatasetRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    parent_identity: Optional[str] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    items: list[DatasetItem] = Field(min_length=1)
    split_policy: Literal["task_disjoint_v1"] = "task_disjoint_v1"

    @model_validator(mode="after")
    def no_exact_leakage(self) -> "DatasetRevision":
        if len({item.content_id for item in self.items}) != len(self.items):
            raise ValueError("duplicate content identity in dataset")
        if len({item.source_identity for item in self.items}) != len(self.items):
            raise ValueError("source trajectory appears in multiple splits")
        task_splits: dict[str, set[Split]] = {}
        for item in self.items:
            task_splits.setdefault(item.task_id, set()).add(item.split)
        if any(len(splits) != 1 for splits in task_splits.values()):
            raise ValueError("task appears in multiple dataset splits")
        if not any(item.split is Split.TRAIN for item in self.items):
            raise ValueError("dataset requires a train split")
        return self


def store_dataset(store: ContentAddressedStore, dataset: DatasetRevision) -> str:
    for item in dataset.items:
        store.get_bytes(item.content_id)
    if dataset.parent_identity is not None:
        store.get_bytes(dataset.parent_identity)
    return store.put_json(dataset.model_dump(mode="json"))


def load_dataset(store: ContentAddressedStore, identity: str) -> DatasetRevision:
    dataset = DatasetRevision.model_validate(store.get_json(identity))
    for item in dataset.items:
        store.get_bytes(item.content_id)
    return dataset
