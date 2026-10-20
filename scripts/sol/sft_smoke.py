"""One-step trusted LoRA SFT pilot for the checked-in tiny fixture.

This verifies the model-loading and training path only. The two examples are
not a reviewed research corpus, and this run is not evidence that AutoSeal
improves coding agents or reduces reward hacking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random


def load_examples(path: Path) -> tuple[list[dict[str, str]], str]:
    source = path.read_bytes()
    examples: list[dict[str, str]] = []
    for line_number, line in enumerate(source.splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        if not isinstance(item, dict) or set(item) != {"prompt", "completion"}:
            raise ValueError(f"line {line_number}: only prompt and completion are allowed")
        if any(not isinstance(item[key], str) or not item[key].strip() for key in item):
            raise ValueError(f"line {line_number}: prompt and completion must be nonempty text")
        examples.append(item)
    if not examples:
        raise ValueError("the SFT pilot needs at least one example")
    return examples, "sha256:" + hashlib.sha256(source).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--dataset-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=17)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not args.model_path.is_dir():
        raise ValueError("model snapshot must be a local directory")
    if args.output_dir.exists():
        raise FileExistsError("refusing to overwrite an existing SFT pilot output")
    examples, dataset_digest = load_examples(args.dataset_path)

    import torch
    from datasets import Dataset
    from peft import LoraConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed
    from trl import SFTConfig, SFTTrainer

    if not torch.cuda.is_available():
        raise RuntimeError("SFT smoke run requires an allocated CUDA GPU")
    random.seed(args.seed)
    set_seed(args.seed)
    tokenizer = AutoTokenizer.from_pretrained(args.model_path, local_files_only=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        args.model_path,
        torch_dtype=torch.bfloat16,
        local_files_only=True,
    )

    args.output_dir.mkdir(parents=True)
    training_args = SFTConfig(
        output_dir=str(args.output_dir / "trainer"),
        max_steps=1,
        max_length=256,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=1,
        learning_rate=2e-4,
        bf16=True,
        save_strategy="no",
        logging_steps=1,
        report_to="none",
        seed=args.seed,
        dataset_num_proc=1,
    )
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=Dataset.from_list(examples),
        processing_class=tokenizer,
        peft_config=LoraConfig(
            r=8,
            lora_alpha=16,
            lora_dropout=0.0,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=["q_proj", "v_proj"],
        ),
    )
    result = trainer.train()
    adapter_path = args.output_dir / "adapter"
    trainer.save_model(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    summary = {
        "schema_version": 1,
        "scope": "TRUSTED_SFT_SMOKE_ONLY",
        "model_snapshot": str(args.model_path),
        "dataset_sha256": dataset_digest,
        "example_count": len(examples),
        "seed": args.seed,
        "global_step": result.global_step,
        "training_loss": result.training_loss,
        "gpu_name": torch.cuda.get_device_name(0),
        "adapter_path": str(adapter_path),
    }
    (args.output_dir / "result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
