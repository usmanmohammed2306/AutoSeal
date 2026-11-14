"""Immutable managed revisions and atomic activation/rollback.

The manager owns this directory and its CAS. Candidate containers must never
receive either path. Rollback covers the declared artifacts and cache
namespace, not process memory or undeclared external effects.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import tempfile
from typing import Callable, Literal, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.projection import safe_relative_artifact_path
from autoseal.repair_engine import (
    AdvertisedCapabilities, AppliedRepairPlan, TypedRepairPlan, VerifierPolicy,
    apply_typed_plan, rollback_policy,
)
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


DIGEST = r"^sha256:[0-9a-f]{64}$"


class EnvironmentRevision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    kind: Literal["managed_environment_revision"] = "managed_environment_revision"
    image_identity: str = Field(pattern=DIGEST)
    task_identity: str = Field(pattern=DIGEST)
    policy: VerifierPolicy
    artifacts: dict[str, str]
    parent_identity: Optional[str] = Field(default=None, pattern=DIGEST)
    applied_plan_identity: Optional[str] = Field(default=None, pattern=DIGEST)

    @model_validator(mode="after")
    def validate_artifacts(self):
        if not self.artifacts or any(not safe_relative_artifact_path(p) for p in self.artifacts):
            raise ValueError("revision requires canonical artifact paths")
        if any(not value.startswith("sha256:") or len(value) != 71 for value in self.artifacts.values()):
            raise ValueError("artifact identity is invalid")
        if (self.parent_identity is None) != (self.applied_plan_identity is None):
            raise ValueError("child revision needs both parent and applied plan")
        return self


class RevisionTransition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    kind: Literal["managed_revision_transition"] = "managed_revision_transition"
    action: Literal["activate", "rollback"]
    before: Optional[str] = Field(pattern=DIGEST)
    after: str = Field(pattern=DIGEST)
    restored_artifacts: dict[str, str]
    cache_namespace: str
    admission_identity: Optional[str] = Field(default=None, pattern=DIGEST)


class RevisionManager:
    """One atomic revision pointer, with optimistic concurrency and a lock."""

    def __init__(self, root: Path, store: ContentAddressedStore, *,
                 admission_verifier: Optional[Callable[[str, str], None]] = None):
        if root.is_symlink():
            raise ValueError("manager root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True)
        self.root, self.store = root, store
        self.admission_verifier = admission_verifier

    @contextmanager
    def _locked(self):
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
        descriptor = os.open(self.root / "manager.lock", flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def load(self, identity: str) -> EnvironmentRevision:
        revision = EnvironmentRevision.model_validate(self.store.get_json(identity))
        for ref in revision.artifacts.values():
            self.store.get_bytes(ref)
        self.store.get_bytes(revision.task_identity)
        if revision.parent_identity is not None:
            # Check the immediate immutable parent and the actual typed overlay.
            parent = EnvironmentRevision.model_validate(self.store.get_json(revision.parent_identity))
            applied = AppliedRepairPlan.model_validate(self.store.get_json(revision.applied_plan_identity))
            if (parent.policy.identity != applied.parent_policy_identity or
                    revision.policy != applied.child or parent.artifacts != revision.artifacts or
                    parent.image_identity != revision.image_identity or parent.task_identity != revision.task_identity):
                raise IntegrityError("child revision disagrees with its managed overlay")
        return revision

    def create(self, *, image_identity: str, task: bytes, policy: VerifierPolicy,
               artifacts: Mapping[str, bytes]) -> str:
        if not artifacts or any(not safe_relative_artifact_path(name) for name in artifacts):
            raise ValueError("revision requires canonical artifact paths")
        if any(len(data) > 2 * 1024 * 1024 for data in artifacts.values()):
            raise ValueError("managed artifact exceeds the 2 MiB budget")
        revision = EnvironmentRevision(
            image_identity=image_identity, task_identity=self.store.put_bytes(task), policy=policy,
            artifacts={name: self.store.put_bytes(data) for name, data in sorted(artifacts.items())},
        )
        identity = self.store.put_json(revision.model_dump(mode="json"))
        self.load(identity)
        return identity

    def apply(self, parent_identity: str, plan: TypedRepairPlan,
              capabilities: AdvertisedCapabilities) -> str:
        """Create a child only. This does not activate it or prove enforcement."""

        parent = self.load(parent_identity)
        applied = apply_typed_plan(parent.policy, plan, capabilities)
        applied_id = self.store.put_json(applied.model_dump(mode="json"))
        child = parent.model_copy(update={"policy": applied.child, "parent_identity": parent_identity,
                                         "applied_plan_identity": applied_id})
        identity = self.store.put_json(child.model_dump(mode="json"))
        self.load(identity)
        return identity

    @staticmethod
    def cache_namespace(identity: str) -> str:
        return "revision/" + identity

    def active(self) -> Optional[str]:
        path = self.root / "active.json"
        if path.is_symlink():
            raise IntegrityError("active revision pointer is a symlink")
        if not path.exists():
            return None
        body = json.loads(path.read_bytes())
        if set(body) != {"revision", "cache_namespace", "transition"}:
            raise IntegrityError("invalid active revision pointer")
        self.load(body["revision"])
        receipt = RevisionTransition.model_validate(self.store.get_json(body["transition"]))
        if (receipt.after != body["revision"] or receipt.cache_namespace != body["cache_namespace"] or
                body["cache_namespace"] != self.cache_namespace(body["revision"]) or
                receipt.restored_artifacts != self.load(body["revision"]).artifacts):
            raise IntegrityError("active pointer disagrees with transition evidence")
        if self.admission_verifier is not None and self.load(body["revision"]).parent_identity is not None:
            if receipt.admission_identity is None:
                raise IntegrityError("active child has no admission evidence")
            self.admission_verifier(receipt.admission_identity, body["revision"])
        return body["revision"]

    def _transition(self, before: Optional[str], after: str, action: str,
                    admission_identity: Optional[str] = None) -> str:
        revision = self.load(after)
        receipt = RevisionTransition(action=action, before=before, after=after,
                                     restored_artifacts=revision.artifacts,
                                     cache_namespace=self.cache_namespace(after), admission_identity=admission_identity)
        receipt_id = self.store.put_json(receipt.model_dump(mode="json"))
        body = canonical_json({"revision": after, "cache_namespace": receipt.cache_namespace,
                               "transition": receipt_id})
        with tempfile.NamedTemporaryFile(dir=self.root, delete=False) as temporary:
            temporary.write(body)
            temporary.flush()
            os.fsync(temporary.fileno())
            staged = Path(temporary.name)
        try:
            os.replace(staged, self.root / "active.json")
            descriptor = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            staged.unlink(missing_ok=True)
        return receipt_id

    def activate(self, identity: str, *, expected_active: Optional[str], admission_identity: Optional[str] = None) -> str:
        with self._locked():
            if self.active() != expected_active:
                raise IntegrityError("active revision changed; refusing stale activation")
            if self.admission_verifier is not None and self.load(identity).parent_identity is not None:
                if admission_identity is None:
                    raise IntegrityError("child activation requires verified admission evidence")
                self.admission_verifier(admission_identity, identity)
            return self._transition(expected_active, identity, "activate", admission_identity)

    def rollback(self, *, expected_child: str) -> str:
        with self._locked():
            if self.active() != expected_child:
                raise IntegrityError("active revision drift prevents rollback")
            child = self.load(expected_child)
            if child.parent_identity is None:
                raise ValueError("root revision has no parent to restore")
            parent = self.load(child.parent_identity)
            applied = AppliedRepairPlan.model_validate(self.store.get_json(child.applied_plan_identity))
            if rollback_policy(applied, child.policy) != parent.policy:
                raise IntegrityError("inverse did not restore parent policy")
            return self._transition(expected_child, child.parent_identity, "rollback")
