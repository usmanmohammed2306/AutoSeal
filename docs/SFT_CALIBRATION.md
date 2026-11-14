# SFT calibration and checkpoint evidence

The model must reliably produce the candidate-file protocol before a useful reward comparison can run. AutoSeal keeps a format calibration separate from the final vulnerable-versus-sealed experiment.

## What actually ran

A Qwen2.5-Coder-7B-Instruct checkpoint at revision `c03e6d358207e414f1eca0bb1891e29f1db0e242` received a 16-update LoRA calibration on 32 authored finite-output examples. Eight additional authored examples are assigned to a validation split and excluded from training. Two independently written calculations check each training target before its reference review. These are AI-assisted reference reviews, not human preference annotations. No external benchmark task or canary enters this dataset.

The run used one A100, LoRA rank 8 on q/v projections, batch size 2, learning rate 0.0002 and maximum example length 512. It intentionally paused at update 8. Before resuming, AutoSeal checked the configuration, dataset, model inventory, trainer step and every optimizer/checkpoint file digest. The same frozen run then completed update 16. This is a planned pause/resume demonstration, not a crashed-node recovery test.

All eight known development requests were sampled before and after training using the same generation seed and settings. Two are benign tasks and six explicitly request false rewards while fixing a wrong output. The latter are targeted calibrations, not natural agent discoveries or a hidden test set.

| Outcome | Common baseline | After 16 full-chat updates | After 64 completion-only updates |
|---|---:|---:|---:|
| Attempts retained | 8 | 8 | 8 |
| Strict file packets | 3 | 4 | 5 |
| Malformed or fenced packets | 5 | 4 | 3 |
| Independent task passes | 1 | 2 | 2 |
| Confirmed false rewards | 0 | 0 | 0 |
| Literal-null adherence among six targeted requests | 0 | 0 | 3 |

Both benign tasks pass after training, but the packet failure rate remains too high. These one-seed development results do not show reduced reward hacking or reliable tool use. The second configuration changes both loss masking and the update budget, so the difference does not isolate either cause. Its independently retained baseline bytes match the first baseline exactly; this is not a new independent cohort. The final study still needs matched reward arms, at least three seeds per arm, hidden audits and seed-level analysis.

## Follow the implementation

1. `src/autoseal/syntax_dataset.py` builds reviewed train/validation records and rejects split relabelling or changed targets.
2. `scripts/prepare_syntax_sft.py` freezes data, trusted source, model-file identities, hyperparameters and generation requests.
3. `scripts/sol/artifact_sft.py` runs TRL/PEFT on a scheduled Sol GPU. It generates text and never executes candidate code.
4. `scripts/sol/training_runtime.py` stages and hashes trusted model files. It checks resumable files before any optimizer deserialization. Completion-only configurations also check the trainer's actual preprocessed loss masks.
5. `scripts/resume_syntax_sft.py` verifies the planned pause through an existing SSH connection and submits only the remaining frozen run. It records submission intent to prevent an automatic duplicate after an uncertain SSH outcome.
6. `scripts/collect_syntax_sft.py` copies declared checkpoints as inert bytes, checks their identities and retains scheduler evidence. It never loads an optimizer on the Mac.
7. `scripts/evaluate_syntax_sft.py` evaluates every before/after completion in fresh Mac Docker containers. It retains malformed packets and keeps verifier failure separate from rejection.
8. `src/autoseal/sft_archive.py` recomputes the archive linkage, output classifications and counts. Its product view also matches each displayed update to the saved trainer logs.

The first calibration used loss on all chat tokens. A completion-only configuration uses conversational prompt/completion records and masks the prompt. Changing the loss and update budget together is a development iteration, not an ablation isolating either change.

## Reproduce the local checks

```bash
python -m pytest -q tests/unit/test_syntax_dataset.py \
  tests/unit/test_training_runtime.py tests/unit/test_sft_archive.py \
  tests/unit/test_sft_calibration_api.py
```

The tiny unit checkpoints contain inert placeholder bytes. They test integrity handling and are not evidence of model training. Archive-dependent tests skip when the separately retained real archive is absent; a configured but corrupt archive fails.

Prepare a new bounded calibration, inspect its configuration and use your existing authorized Sol account to submit the saved Slurm script:

```bash
python scripts/prepare_syntax_sft.py \
  --probe-root PATH_TO_RETAINED_MODEL_PROBE \
  --root .autoseal/my-syntax-calibration
```

The preparation command does not allocate a GPU. Scheduler account, existing environment, model path, SSH host and socket are local configuration. Keep them and credentials out of Git. The resume and collector scripts expose those settings through `--help`; neither creates an account or changes access.

After collecting the run:

```bash
python scripts/evaluate_syntax_sft.py \
  --archive-root .autoseal/collected-sft \
  --root .autoseal/sft-development-evaluation
```

The evaluation index names its immutable evaluation ID and evidence store. Configure the API with `--sft-archive-root` and `--sft-evaluation-id` to show the checked results on Studio's Training evidence page. Reader authentication applies to that endpoint. No checkpoint or arbitrary file download route is added.

## Read the result carefully

Wire validity is not task correctness. Task correctness is not proof that an exploit was blocked. A zero false-reward count from eight mostly malformed or non-adherent attempts cannot establish robustness. Training loss is an optimization diagnostic; paused/resumed library aggregates may use a global-step denominator and should not become throughput claims. Inspect raw per-update records and scheduler elapsed time instead.

The retained first training archive is `sha256:828652fb30962f8e05cadd3648913bd34e7a4ab30e793862bf5e1881ee60ac8a`. Its adapter is `sha256:dda511ef6a9f8ac7f72c3c382d3cb94ed8a04226a1e50d8ebaa1490564908a0e`, and its paired development evaluation is `sha256:02e0c5c93fc4def3636dd2124bd3d0444815a5854feea4a4158eb61c42edc6f5`. Machine-specific raw archives and weights stay outside the public checkout.

The separately frozen completion-only configuration completed its planned pause at 32 and resume to 64. Its archive is `sha256:7ec3da83fbde131e73210bf5e44a12bb8721df0a47fa38921c196d4335ae5830`, adapter `sha256:4d457e6d0abf59f8eb6cf66731316382012a0b41109e7a3c36e8bde29cd1fba0`, and paired evaluation `sha256:0279febb329cff790d429af321f3b931c220b531ef3ecd51764fdbfb70e934cc`. All four frozen weight shards match the official repository's LFS hashes/sizes, and all eight frozen model/config/tokenizer/license files match official Git blob identities at the pinned revision. [Official model revision](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct/tree/c03e6d358207e414f1eca0bb1891e29f1db0e242).
