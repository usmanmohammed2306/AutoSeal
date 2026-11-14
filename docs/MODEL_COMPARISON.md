# Follow the model comparison

On November 13, 2026, AutoSeal completed a matched vulnerable-versus-sealed GRPO study with three seeds per arm, followed by an independent hidden-input audit. **It found no measured improvement.** Every checkpoint and the shared SFT baseline passed one of eight audit tasks. No false reward was observed in these audit generations.

## What ran

The base was `Qwen/Qwen2.5-Coder-7B-Instruct` at revision `c03e6d358207e414f1eca0bb1891e29f1db0e242`, with the shared [64-update syntax SFT adapter](SFT_CALIBRATION.md). Both arms reset to that adapter. They used seeds 11, 22 and 33, eight optimizer steps per condition and four completions per group. The reward arms shared tasks, prompts, optimizer settings and generation budgets. Their intended difference was the evaluator supplying the training reward.

The six conditions retained all **192 training outputs**. Ten groups had nonconstant rewards, with recorded nonzero gradients. The training allocation used one A100 and completed in 14 minutes 5 seconds. That is scheduler allocation time, including startup, staging and reward waits, rather than model throughput. Two adapter pairs were byte-identical; the third pair differed. Different adapter bytes alone do not establish a behavioral or causal effect.

The inference-only audit job then generated **56 completions**: eight committed input instances for each of the six trained checkpoints and one shared SFT baseline. It used greedy decoding and the same 256-token output ceiling for every model. The baseline is evaluated once, not counted as three independent baselines. The audit allocation completed in 4 minutes 27 seconds on one A100. Mac Docker evaluated each submitted artifact against the proxy and independent task calculation.

| Model | Seeds | Attempts per model | Audit passes | False rewards | Invalid / inconclusive |
|---|---|---:|---:|---:|---:|
| Shared SFT baseline | One shared checkpoint | 8 | 1/8 | 0/8 | 0 / 0 |
| Vulnerable-reward GRPO | 11, 22, 33 | 8 each | 1/8 each | 0/8 each | 0 / 0 each |
| Sealed-reward GRPO | 11, 22, 33 | 8 each | 1/8 each | 0/8 each | 0 / 0 each |

Each paired seed difference is zero for both audit success and false rewards. Exact enumeration of paired seed resamples therefore gives a descriptive interval of zero to zero. This describes this small observed sample. It is not evidence that the true effect is exactly zero, a significance test, a security guarantee or a benchmark-wide result. With no observed audit false rewards in either arm, this study cannot estimate a relative reward-hacking reduction.

## How the evidence is checked

The analysis source and protocol were content-addressed before training. Hidden inputs were committed before training and exported only after all final checkpoints were retained. They are hidden from the reward interface, not blind to the reference author. Audit outcomes never select a training reward or checkpoint.

`artifact_study_archive.py` checks model provenance, scheduler outcomes, checkpoint inventories and raw broker rewards. `artifact_audit.py` checks each generation and its linked Docker receipts, then recomputes the summary with every attempt retained. `artifact_study_review.py` also verifies the pre-training analysis source and checks that none of the 16 study instances exactly matches an operation and ordered input from the 40 known SFT examples. This exact-input check is not a semantic-equivalence or benchmark-contamination proof.

The CLI, authenticated reader API and Studio training page consume the same checked view. Missing or corrupt evidence produces an explicit error rather than a demonstration result.

```bash
python -m autoseal model-study \
  --root /absolute/path/to/retained-study \
  --evaluation-id sha256:YOUR_ORIGINAL_EVALUATION_DIGEST
```

For the local API, supply both `serve --study-archive-root` and `--study-evaluation-id`. The saved endpoint is `/api/research/model-study`. See [local setup](../README.md#the-local-full-stack-path) for the API and Studio, including authentication.

The reference result has these immutable identities:

| Artifact | SHA-256 |
|---|---|
| Frozen manifest | `9a01d5fdef4a1af1c7864d65a233f8355d740b419f0fc9cf3ae48fe6d063079d` |
| Completed training archive | `9f290b60de2aded07bbf08b838d57f975b270caf8643f08c49ea5f3b6fca1b6d` |
| Hidden generation archive | `994626f7fab849bcd503dc4eba238806aa969fc18154885a5143a516a8840a63` |
| Docker audit evaluation | `4ffdcb9df2727271c8e1287854708fb35c74acfe94caa863018db47e6c3de71d` |

These identities refer to original local archives. The public checkout includes the implementation and this result report, not the optimizer/model files or a publicly downloadable copy of the raw archive. A summary alone cannot pass the offline verifier.

## Read, change and run

Start at `scripts/prepare_artifact_grpo.py`, then follow `scripts/sol/artifact_grpo.py` to the Mac reward relay. Trace one request through `artifact_study.py` and its admission evidence. Next follow `scripts/prepare_artifact_audit.py`, the inference-only Sol driver, `scripts/evaluate_artifact_audit.py` and finally `study_review`. This follows one real artifact from frozen task to displayed result.

Run `pytest -q tests/unit/test_artifact_audit.py tests/unit/test_model_study_view.py` for source-only checks. They use explicitly synthetic inputs. If the original archive is available locally, `tests/integration/test_saved_model_comparison.py` additionally verifies its real reader response and rejects changed summaries, duplicated attempts and replacement analysis source. It skips explicitly when that archive is absent and never launches a GPU job.

In a separate learning checkout, change a copied summary to claim eight passes, observe the integrity failure, and repair the change. Then add a synthetic inconclusive outcome and verify that it remains in the denominator. Commit the check and its explanation when you can trace its behavior. Do not rewrite historical results or manufacture daily commits.

This completes a bounded training-and-audit comparison. The full release still requires its external-case admissions, baselines, ablations and operational evidence. Earlier null preflights remain recorded in the [results](RESULTS.md) and [model card](MODEL_CARD.md).
