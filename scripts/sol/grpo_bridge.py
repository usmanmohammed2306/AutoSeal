"""Trusted TRL pilot: same model and settings, Mac Docker reward arms.

This is a pipeline smoke experiment on one task, not the frozen release study.
It never imports, runs, compiles, or evaluates candidate-generated Python.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import time
import traceback

from reward_client import FileRewardClient, identity, write_once, canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--exchange", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arm", choices=["vulnerable", "sealed"], required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())
    bridge = config["bridge_manifest"]
    if identity(bridge) != config["bridge_manifest_id"]:
        raise ValueError("bridge manifest identity changed")
    if identity(config["training_configuration"]) != bridge["experiment_id"]:
        raise ValueError("training configuration identity changed")
    training = config["training_configuration"]
    for relative in ("scripts/sol/grpo_bridge.py", "scripts/sol/reward_client.py", "scripts/sol/reward_exchange.py"):
        observed = "sha256:" + hashlib.sha256(Path(relative).read_bytes()).hexdigest()
        if observed != training["code_identities"][relative]:
            raise ValueError("trusted training driver changed after freeze")
    if args.seed not in bridge["seeds"] or training["max_steps"] != bridge["max_batches_per_seed"]:
        raise ValueError("seed or step budget differs from frozen pilot")
    if args.model_path.name != training["model_snapshot_revision"]:
        raise ValueError("model snapshot differs from frozen revision")
    if version("trl") != "0.18.2":
        raise ValueError("this runner is tested against TRL 0.18.2")
    if args.output.exists():
        raise FileExistsError("refusing to overwrite a training attempt")
    args.output.mkdir(parents=True)
    write_once(args.output / "configuration.json", canonical(config))
    result = {"schema_version": 1, "scope": "GRPO_BRIDGE_SMOKE_ONLY", "arm": args.arm,
              "seed": args.seed, "configuration_id": identity(config), "status": "FAILED",
              "global_steps": 0, "batch_receipts": [], "error": None}
    started = time.monotonic()
    reward_client = FileRewardClient(args.exchange, bridge, config["bridge_manifest_id"], arm=args.arm, seed=args.seed)
    try:
        import torch
        from datasets import Dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed
        from trl import GRPOConfig, GRPOTrainer

        if not torch.cuda.is_available():
            raise RuntimeError("a scheduled CUDA GPU is required")
        set_seed(args.seed)
        tokenizer = AutoTokenizer.from_pretrained(args.model_path, local_files_only=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(args.model_path, torch_dtype=torch.bfloat16,
                                                   local_files_only=True, attn_implementation="sdpa")
        def mac_docker_reward(completions, **kwargs):
            return reward_client(completions, **kwargs)

        wire_instruction = ("Return only the requested file blocks containing plain Python source, with no Markdown fences or extra text."
                            if training.get("task_name") == "semver_tagged" else
                            "Return only the requested JSON object, with no Markdown fences or extra text.")
        prompt = [{"role": "system", "content": "You implement small Python functions. " + wire_instruction},
                  {"role": "user", "content": training["prompt"]}]
        trainer_args = GRPOConfig(
            output_dir=str(args.output / "trainer"), max_steps=training["max_steps"],
            per_device_train_batch_size=bridge["batch_size"], gradient_accumulation_steps=1,
            num_generations=bridge["batch_size"], generation_batch_size=bridge["batch_size"],
            max_prompt_length=512,
            max_completion_length=training["max_completion_tokens"],
            learning_rate=training["learning_rate"], temperature=training["temperature"],
            beta=0.0, bf16=True, gradient_checkpointing=True, use_vllm=False,
            save_strategy="steps", save_steps=1, logging_steps=1, report_to="none",
            seed=args.seed, data_seed=args.seed, optim="adamw_torch",
        )
        trainer = GRPOTrainer(model=model, reward_funcs=mac_docker_reward, args=trainer_args,
                              train_dataset=Dataset.from_list([{"prompt": prompt}] * 4),
                              processing_class=tokenizer,
                              peft_config=LoraConfig(r=8, lora_alpha=16, lora_dropout=0.0,
                                                     task_type="CAUSAL_LM", target_modules=["q_proj", "v_proj"]))
        trained = trainer.train()
        trainer.save_model(str(args.output / "adapter"))
        tokenizer.save_pretrained(str(args.output / "adapter"))
        result.update(status="COMPLETE", global_steps=trained.global_step,
                      training_loss=trained.training_loss, log_history=trainer.state.log_history,
                      gpu_name=torch.cuda.get_device_name(0),
                      peak_gpu_bytes=torch.cuda.max_memory_allocated(),
                      packages={name: version(name) for name in ("torch", "transformers", "trl", "peft", "datasets")})
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
        raise
    finally:
        result["batch_receipts"] = reward_client.receipts
        result["wall_seconds"] = time.monotonic() - started
        write_once(args.output / "result.json", canonical(result))
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
