# AutoSeal

### Fine-Tuning Regression Detection and Repair

**Help a model learn a new task without losing behaviors it already handled.**

Fine-tuning can improve a model's average score while breaking answers it previously got right. AutoSeal is being developed to identify those regressions, propose a correction to the LoRA update, and show whether the correction preserves the newly learned skill.

**Status: research and development.** This repository currently publishes only this project overview. The model-repair method and integrated application have not passed completion gates. The figures below are engineering and research targets, not achieved results or predictions.

## A concrete example

Suppose a model learns to classify customer-support requests after fine-tuning, but starts failing reasoning questions it previously answered correctly. AutoSeal's intended workflow is to compare the original model, the fine-tuned model and a proposed correction on the same cases. A correction qualifies only if it restores previously correct behavior and retains the required new-task improvement on held-out evaluations.

## Intended workflow

1. **Compare:** bind the original model, fine-tuned adapter, datasets and evaluation settings to a versioned run.
2. **Detect:** identify individual responses that became incorrect, alongside new-task gains and newly introduced failures.
3. **Correct:** optimize a constrained LoRA correction using development data, then freeze the candidate before final evaluation.
4. **Decide:** promote a correction only when held-out regression and skill-retention checks pass. Otherwise retain the existing version and report the failure.
5. **Review:** inspect before-and-after evidence, replay archived evaluations and roll back to the exact previous model artifact.

Preservation means performance on specified evaluated behaviors. It cannot guarantee that every untested model capability survives.

## Completion targets

These goals define the intended completed project. Successful measurement may instead establish a null or adverse result, which will be reported.

| Area | Target |
| --- | --- |
| Regression reduction | At least **40% relative reduction** in the mean regression rate against uncorrected fine-tunes on the frozen evaluation set |
| Evaluation coverage | **36 fresh held-out updates** across **4 backbones**, **3 adaptation tasks** and **3 seeds** per model/task combination |
| Repair qualification | Beneficial corrections passing all declared gates on at least **27 of 36 updates**; failures and no-op corrections remain in the denominator |
| New-task preservation | At least **95% of new-task gains retained for every promoted correction**, with a declared minimum gain for eligibility |
| Comparisons | **4 preservation baselines**, with task-performance matching and training/search budgets reported |
| Replay | **100/100 distinct archived evaluation runs** reproduced under documented replay tolerances |
| Recovery | **20/20 injected worker-failure trials across 5 scenarios**, preserving evidence without duplicate committed effects |

A regression rate counts failures among cases the original model answered correctly. Relative reduction compares that rate before and after correction. Retained gain compares the corrected model's improvement over the original model with the uncorrected fine-tune's improvement. Aggregate scores, individual updates and uncertainty must be reported together.

## Current evidence and next milestone

A preliminary study evaluated **18 LoRA updates across 2 small backbones, 3 classification tasks and 3 seeds**. The primary correction left the mean regression rate unchanged at **13.22%**, and **0/18 updates** produced a beneficial repair passing all required gates. A separate science-question audit showed a small effect whose uncertainty interval included zero. This does not establish reliable automatic repair or support the completion targets as forecasts.

The next research milestone is a revised correction method evaluated against stronger applicable baselines on fresh held-out updates. The earlier evaluation-integrity prototype and its results are separate from acceptance of this model-repair platform.

## Planned application and stack

**Python · PyTorch · PEFT · Next.js · FastAPI · PostgreSQL · Docker**

The completed application is intended to provide authenticated review, recoverable training and evaluation jobs, versioned model artifacts, evidence linked by content hashes, guarded promotion and verified rollback. Reliability checks from earlier infrastructure work do not establish acceptance of this new end-to-end workflow.

This README-only branch is a project overview, not an installable release. Implementation files and research archives are not included in its current file tree.
