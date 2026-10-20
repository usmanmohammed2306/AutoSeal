"""TRL reward callback transport. This module never executes generated code."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import time
import uuid


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def identity(value) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def write_once(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError("exchange artifact already exists with different content")
        return
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_bytes(content)
        # A hard link is an atomic no-overwrite publish operation on scratch.
        try:
            import os
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise ValueError("conflicting exchange artifact")
    finally:
        temporary.unlink(missing_ok=True)


def validate_response(envelope: dict, request_id: str, manifest_id: str, count: int) -> list[float]:
    if set(envelope) != {"response_id", "response"} or identity(envelope["response"]) != envelope["response_id"]:
        raise ValueError("response content identity mismatch")
    response = envelope["response"]
    if response["request_id"] != request_id or response["bridge_manifest_id"] != manifest_id:
        raise ValueError("response belongs to a different request or evaluator")
    if response["kind"] != "reward_response" or response["schema_version"] != 1:
        raise ValueError("unsupported response protocol")
    if response["status"] != "COMPLETE":
        raise RuntimeError("Mac evaluator failed; do not substitute a zero reward")
    rewards = response["rewards"]
    if len(rewards) != count or len(response["outcomes"]) != count or len(response["evidence_ids"]) != count:
        raise ValueError("reward batch length mismatch")
    for reward, outcome in zip(rewards, response["outcomes"]):
        valid = (isinstance(reward, (int, float)) and not isinstance(reward, bool) and math.isfinite(reward) and
                 (reward == 1.0 if outcome == "PASS" else
                  reward == 0.0 if outcome == "INVALID_OUTPUT" else
                  0.0 <= reward < 1.0 if outcome == "REJECT" else False))
        if not valid:
            raise ValueError("invalid reward or evaluator outcome")
    return [float(value) for value in rewards]


class FileRewardClient:
    def __init__(self, exchange: Path, manifest: dict, manifest_id: str, *, arm: str, seed: int, timeout_seconds: float = 300):
        if identity(manifest) != manifest_id or arm not in {"vulnerable", "sealed"} or seed not in manifest["seeds"]:
            raise ValueError("unfrozen bridge configuration")
        if not 0 < timeout_seconds <= 600:
            raise ValueError("reward wait must be bounded")
        self.exchange, self.manifest, self.manifest_id = exchange, manifest, manifest_id
        self.arm, self.seed, self.timeout_seconds = arm, seed, timeout_seconds
        self.batch = 0
        self.receipts = []

    def __call__(self, completions, **kwargs):
        if self.batch >= self.manifest["max_batches_per_seed"]:
            raise RuntimeError("frozen rollout budget exhausted")
        texts = [item if isinstance(item, str) else item[0]["content"] for item in completions]
        if len(texts) != self.manifest["batch_size"]:
            raise ValueError("TRL generation group differs from frozen batch size")
        request = {"schema_version": 1, "kind": "reward_request", "bridge_manifest_id": self.manifest_id,
                   "experiment_id": self.manifest["experiment_id"], "arm": self.arm, "seed": self.seed,
                   "batch": self.batch, "task_id": self.manifest["task_id"], "completions": texts}
        request_id = identity(request)
        name = request_id[7:] + ".json"
        write_once(self.exchange / "requests" / name, canonical(request))
        response_path = self.exchange / "responses" / name
        deadline = time.monotonic() + self.timeout_seconds
        while not response_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Mac reward worker did not respond to {request_id}")
            time.sleep(0.25)
        envelope = json.loads(response_path.read_bytes())
        rewards = validate_response(envelope, request_id, self.manifest_id, len(texts))
        self.receipts.append({"batch": self.batch, "request_id": request_id, "response_id": envelope["response_id"]})
        self.batch += 1
        return rewards
