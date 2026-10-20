"""Freeze a small transport experiment. This cannot certify the release study."""

import argparse
import json
from pathlib import Path

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import _tree_digest
from autoseal.reward_tasks import get_reward_task
from autoseal.reward_bridge import RewardBridgeManifest
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task", choices=("is_even", "semver", "semver_tagged"), default="is_even")
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 22, 33])
    parser.add_argument("--max-completion-tokens", type=int, default=256)
    parser.add_argument("--reward-scheme", choices=("binary", "pytest_pass_fraction_v1"), default="binary")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("do not overwrite a frozen pilot")
    if tuple(args.seeds) != tuple(sorted(set(args.seeds))) or not 128 <= args.max_completion_tokens <= 2048:
        raise ValueError("seeds must be sorted and unique; completion tokens must be 128 to 2048")
    root = Path(__file__).resolve().parents[1]
    task = get_reward_task(args.task)
    store = ContentAddressedStore(args.store)
    code = {name: store.put_bytes((root / name).read_bytes())
            for name in ("scripts/sol/grpo_bridge.py", "scripts/sol/reward_client.py", "scripts/sol/reward_exchange.py",
                         "src/autoseal/reward_bridge.py", "src/autoseal/sol_reward_worker.py", "src/autoseal/docker_fixture.py",
                         "src/autoseal/reward_tasks.py", "src/autoseal/candidate_wire.py",
                         "src/autoseal/result_binding.py", "src/autoseal/repair_engine.py")}
    prompt = task.prompt
    training = {"scope": "GRPO_BRIDGE_SMOKE_ONLY", "task_name": task.name,
                "expected_passes": task.expected_passes,
                "reward_scheme": args.reward_scheme,
                "model_snapshot_revision": "488639f1ff808d1d3d0ba301aef8c11461451ec5",
                "seeds": args.seeds, "max_steps": 2, "max_completion_tokens": args.max_completion_tokens,
                "learning_rate": 1e-5, "temperature": 0.7, "prompt": prompt,
                "optimizer": "adamw_torch", "lora_rank": 8, "lora_alpha": 16, "beta": 0.0,
                "stop_rule": "Stop the entire pilot on the first failed condition; retain all attempts and unrun conditions.",
                "code_identities": code, "limitation": "One task, no held-out research audit, no downstream improvement claim."}
    experiment_id = store.put_json(training)
    manifest = RewardBridgeManifest(scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
                                   experiment_id=experiment_id, task_id=store.put_bytes(prompt.encode()),
                                   verifier_identity=_tree_digest(task.verifier),
                                   image_identity=image_identity(DEFAULT_IMAGE), seeds=tuple(args.seeds),
                                   max_batches_per_seed=2, batch_size=2)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    config = {"schema_version": 1, "training_configuration": training,
              "bridge_manifest_id": manifest_id, "bridge_manifest": manifest.model_dump(mode="json")}
    config_id = store.put_json(config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(config))
    print(json.dumps({"configuration_id": config_id, "bridge_manifest_id": manifest_id, "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
