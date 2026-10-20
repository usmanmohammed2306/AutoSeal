"""Verify all six paired pilot reports against frozen reward request receipts.

This deliberately cannot certify the frozen release study. It detects an
important failure mode: a trainer can complete six runs while every sampled
candidate receives the same reward and no policy update has a useful signal.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from autoseal.reward_bridge import RewardBridgeManifest, RewardRequest, RewardResponse
from autoseal.storage import ContentAddressedStore, IntegrityError


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def analyze(store: ContentAddressedStore, output_root: Path, configuration_id: str) -> dict:
    config = store.get_json(configuration_id)
    if config["schema_version"] != 1 or config["training_configuration"]["scope"] != "GRPO_BRIDGE_SMOKE_ONLY":
        raise ValueError("not a frozen GRPO reward-bridge pilot")
    manifest_id = config["bridge_manifest_id"]
    manifest = RewardBridgeManifest.model_validate(store.get_json(manifest_id))
    if manifest.model_dump(mode="json") != config["bridge_manifest"]:
        raise IntegrityError("saved bridge manifest differs from training config")
    if manifest.experiment_id != store.put_json(config["training_configuration"]):
        raise IntegrityError("training configuration identity changed")
    rows = []
    for seed in manifest.seeds:
        for arm in ("vulnerable", "sealed"):
            run = output_root / f"{arm}_{seed}"
            result = json.loads((run / "result.json").read_text())
            if (result["arm"] != arm or result["seed"] != seed or result["configuration_id"] != configuration_id
                or result["status"] != "COMPLETE" or result["global_steps"] != manifest.max_batches_per_seed):
                raise IntegrityError("training report disagrees with frozen condition")
            if len(result["batch_receipts"]) != manifest.max_batches_per_seed:
                raise IntegrityError("missing reward batches")
            outcomes, rewards, reward_stds = [], [], []
            for expected_batch, pair in enumerate(result["batch_receipts"]):
                request = RewardRequest.model_validate(store.get_json(pair["request_id"]))
                response = RewardResponse.model_validate(store.get_json(pair["response_id"]))
                if (pair["batch"] != expected_batch or request.batch != expected_batch
                    or request.arm != arm or request.seed != seed or request.bridge_manifest_id != manifest_id
                    or response.request_id != pair["request_id"] or response.bridge_manifest_id != manifest_id
                    or response.status != "COMPLETE"):
                    raise IntegrityError("reward receipt differs from frozen training batch")
                for identity in response.evidence_ids:
                    store.get_json(identity)
                outcomes.extend(response.outcomes)
                rewards.extend(response.rewards)
            for item in result["log_history"]:
                if "reward_std" in item:
                    reward_stds.append(float(item["reward_std"]))
            adapter = run / "adapter" / "adapter_model.safetensors"
            if not adapter.is_file():
                raise IntegrityError("trained adapter artifact is missing")
            rows.append({"arm": arm, "seed": seed, "global_steps": result["global_steps"],
                         "outcomes": dict(sorted(Counter(outcomes).items())),
                         "reward_sum": sum(rewards), "samples": len(rewards),
                         "reward_stds": reward_stds, "train_loss": result["training_loss"],
                         "adapter_identity": _hash_file(adapter), "adapter_bytes": adapter.stat().st_size,
                         "gpu_name": result["gpu_name"],
                         "peak_gpu_bytes": result["peak_gpu_bytes"]})
    has_signal = any(any(value > 0 for value in row["reward_stds"]) for row in rows)
    paired_identical = [seed for seed in manifest.seeds if
                        next(item for item in rows if item["arm"] == "vulnerable" and item["seed"] == seed)["adapter_identity"] ==
                        next(item for item in rows if item["arm"] == "sealed" and item["seed"] == seed)["adapter_identity"]]
    return {"schema_version": 1, "scope": "GRPO_BRIDGE_SMOKE_ONLY", "configuration_id": configuration_id,
            "bridge_manifest_id": manifest_id, "model_snapshot_revision": config["training_configuration"]["model_snapshot_revision"],
            "paired_conditions_complete": len(rows) == 2 * len(manifest.seeds),
            "nonzero_within_batch_reward_variance": has_signal,
            "identical_paired_adapter_seeds": paired_identical,
            "downstream_improvement_established": False,
            "limitation": "One reviewed local task, no held-out audit, no benchmark-scale corpus; this is a transport and training smoke test.",
            "conditions": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--configuration-id", required=True)
    args = parser.parse_args()
    print(json.dumps(analyze(ContentAddressedStore(args.store), args.output_root, args.configuration_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
