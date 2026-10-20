"""Trusted-manager receipts bound to all six evaluator identities.

Content binding prevents stale or cross-task result reuse. It is not a signature
or proof that the producing manager is trustworthy. Candidate containers never
receive this store or its cache index.
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from autoseal.evidence import CommandEvidence
from autoseal.evaluation import TestCounts, Verdict
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


DIGEST = r"^sha256:[0-9a-f]{64}$"


class ResultContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    task: str = Field(pattern=DIGEST)
    candidate: str = Field(pattern=DIGEST)
    verifier: str = Field(pattern=DIGEST)
    policy: str = Field(pattern=DIGEST)
    provider: str = Field(pattern=DIGEST)
    environment: str = Field(pattern=DIGEST)

    @property
    def identity(self) -> str:
        return "sha256:" + hashlib.sha256(
            b"autoseal.result-context.v1\0" + canonical_json(self.model_dump(mode="json"))
        ).hexdigest()


class BoundResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    kind: Literal["bound_evaluation_result"] = "bound_evaluation_result"
    owner: Literal["trusted_verifier"] = "trusted_verifier"
    context: ResultContext
    context_identity: str = Field(pattern=DIGEST)
    channel: Literal["proxy", "audit", "sealed"]
    evaluation_id: str = Field(pattern=DIGEST)
    process_id: str = Field(pattern=DIGEST)
    verdict: Verdict


def _validate_payload(evaluation: dict, context: ResultContext) -> None:
    if evaluation["candidate_identity"] != context.candidate:
        raise IntegrityError("result belongs to another candidate")
    process = CommandEvidence.model_validate(evaluation["process"])
    counts = TestCounts.model_validate(evaluation["counts"])
    verdict = Verdict(evaluation["verdict"])
    if verdict is Verdict.PASS and process.status != "exited_zero":
        raise IntegrityError("passing result has no successful process")
    if verdict is Verdict.REJECT and (process.status not in {"exited_zero", "exited_nonzero"}
                                     or counts.failed + counts.skipped == 0):
        raise IntegrityError("rejection has no completed test evidence")
    if process.status in {"timeout", "launch_error"} and verdict in {Verdict.PASS, Verdict.REJECT}:
        raise IntegrityError("process failure is not a semantic verdict")


def bind_result(store: ContentAddressedStore, context: ResultContext, evaluation: dict) -> str:
    """Called only by the trusted manager after execution and freezing."""

    _validate_payload(evaluation, context)
    receipt = BoundResult(
        context=context, context_identity=context.identity, channel=evaluation["channel"],
        evaluation_id=store.put_json(evaluation), process_id=store.put_json(evaluation["process"]),
        verdict=Verdict(evaluation["verdict"]),
    )
    return store.put_json(receipt.model_dump(mode="json"))


def resolve_result(store: ContentAddressedStore, identity: str, expected: ResultContext, *, channel: str) -> dict:
    """No mutable fallback: wrong task, policy, provider, or revision fails closed."""

    receipt = BoundResult.model_validate(store.get_json(identity))
    if receipt.context != expected or receipt.context_identity != expected.identity or receipt.channel != channel:
        raise IntegrityError("result binding mismatch")
    evaluation = store.get_json(receipt.evaluation_id)
    _validate_payload(evaluation, expected)
    if (evaluation["channel"] != receipt.channel or evaluation["verdict"] != receipt.verdict.value
            or store.get_json(receipt.process_id) != evaluation["process"]):
        raise IntegrityError("bound result summary mismatch")
    return evaluation


class BoundResultCache:
    """A bounded manager-owned index, keyed by six identities and channel."""

    def __init__(self, store: ContentAddressedStore, *, max_entries: int = 1024):
        if max_entries < 1:
            raise ValueError("cache needs a positive entry limit")
        self.store = store
        self.max_entries = max_entries
        self._entries: dict[tuple[str, str], str] = {}

    def put(self, context: ResultContext, evaluation: dict) -> str:
        identity = bind_result(self.store, context, evaluation)
        key = (context.identity, evaluation["channel"])
        if key not in self._entries and len(self._entries) >= self.max_entries:
            del self._entries[next(iter(self._entries))]
        self._entries[key] = identity
        return identity

    def get(self, context: ResultContext, *, channel: str) -> dict | None:
        identity = self._entries.get((context.identity, channel))
        return None if identity is None else resolve_result(self.store, identity, context, channel=channel)
