"""Local content-addressed evidence storage with verification on every read."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.evaluation import PairedEvaluation


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


class IntegrityError(ValueError):
    """Stored evidence does not match its published identity."""


class ContentAddressedStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def _path(self, identity: str) -> Path:
        if not identity.startswith("sha256:") or len(identity) != 71:
            raise ValueError("invalid content identity")
        digest = identity[7:]
        if any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("invalid content identity")
        return self.root / "objects" / digest[:2] / digest

    def put_bytes(self, content: bytes) -> str:
        identity = "sha256:" + hashlib.sha256(content).hexdigest()
        destination = self._path(identity)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != content:
                raise IntegrityError("existing object failed content verification")
            return identity
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        try:
            os.replace(temporary_path, destination)
        finally:
            temporary_path.unlink(missing_ok=True)
        return identity

    def get_bytes(self, identity: str) -> bytes:
        content = self._path(identity).read_bytes()
        if "sha256:" + hashlib.sha256(content).hexdigest() != identity:
            raise IntegrityError("stored object digest mismatch")
        return content

    def put_json(self, value: Any) -> str:
        return self.put_bytes(canonical_json(value))

    def get_json(self, identity: str) -> Any:
        return json.loads(self.get_bytes(identity))


class ComparisonManifest(BaseModel):
    """Immutable links to the two evaluator records and their candidate."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    candidate_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    proxy_object: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_object: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    classification: Literal[
        "FALSE_REWARD", "AGREEMENT_PASS", "AGREEMENT_REJECT", "DISAGREEMENT", "INCONCLUSIVE"
    ]


def store_comparison(store: ContentAddressedStore, pair: PairedEvaluation) -> str:
    proxy_id = store.put_json(pair.proxy.model_dump(mode="json"))
    audit_id = store.put_json(pair.audit.model_dump(mode="json"))
    manifest = ComparisonManifest(
        candidate_identity=pair.proxy.candidate_identity,
        proxy_object=proxy_id,
        audit_object=audit_id,
        classification=pair.classification,
    )
    return store.put_json(manifest.model_dump(mode="json"))


def load_comparison(store: ContentAddressedStore, manifest_id: str) -> PairedEvaluation:
    manifest = ComparisonManifest.model_validate(store.get_json(manifest_id))
    pair = PairedEvaluation.model_validate(
        {
            "proxy": store.get_json(manifest.proxy_object),
            "audit": store.get_json(manifest.audit_object),
            "classification": manifest.classification,
        }
    )
    if pair.proxy.candidate_identity != manifest.candidate_identity:
        raise IntegrityError("manifest candidate identity mismatch")
    return pair
