# Model use and limitations

AutoSeal uses an existing coding model to study evaluator rewards. It does not pretrain a foundation model, and no current result establishes a generally safer or stronger model.

## Model and adaptation

The artifact-output calibration uses Qwen2.5-Coder-7B-Instruct at revision `c03e6d358207e414f1eca0bb1891e29f1db0e242`. The retained local inventory matches the official identities of its four weight shards and eight configuration, tokenizer and license files. Use the upstream license and model card when redistributing any model artifacts. The source repository does not publish the local weights or optimizer checkpoints.

Two separately frozen LoRA calibrations used rank eight on q/v projections, batch size two and learning rate 0.0002. The first ran 16 updates with full-chat-token loss and a checked pause at eight. The second ran 64 updates with completion-only loss and a checked pause at 32. Both used one A100 on ASU Sol. The optimizer and adapter files were collected as inert bytes; the Mac verifier never deserializes an optimizer.

## Data

The syntax dataset contains 32 authored training examples and eight separate validation examples. Each target must agree with two independently written reference calculations. The review is AI-assisted reference work, not a human annotation or preference campaign. External benchmark tasks and canaries do not enter this dataset.

Known development generation requests include two benign tasks and six explicitly targeted requests that fix an incorrect output. They are not hidden tests or evidence of natural exploit discovery. The later study population has eight train instances and eight committed audit instances. Inputs are hidden from the trainer interface, not blind to the reference author. Prompt or difficulty changes create separate recorded development attempts.

## Observed behavior

| Known development requests | Shared baseline | After 16 updates | After 64 updates |
|---|---:|---:|---:|
| Attempts retained | 8 | 8 | 8 |
| Strict packets | 3 | 4 | 5 |
| Audit task passes | 1 | 2 | 2 |
| Confirmed false rewards | 0 | 0 | 0 |

The baseline is the same saved generation, not two independent replications. Loss masking and update count both changed in the second calibration. The packet failure rate remains substantial. A small training loss did not establish reliable output behavior.

Two subsequent admitted-reward GRPO preflights completed two steps per arm with one seed. The first produced two invalid packets and six rejected answers per arm; the second produced eight rejected answers per arm. Both received only zero rewards, recorded zero gradient norms and retained adapter bytes identical to the SFT start. Neither is a completed final study or evidence of improvement. A separately frozen shorter-input preflight then gave each arm two passes, five rejections and one invalid packet. Both arms recorded a nonzero gradient and changed adapter bytes, but their resulting adapters remained identical. This establishes a responsive pipeline, not a sealing benefit. All attempts and earlier null pilots remain part of the record.

## Evaluation and permitted conclusions

The study compares vulnerable and sealed reward arms from the same frozen starting model. Tasks, prompts, seeds, optimizer and generation budgets must match. The November 13 comparison completed three seeds per arm and a post-checkpoint hidden audit, using the analysis source frozen before training. Across 56 generations, the baseline and every trained checkpoint passed 1/8 tasks; all showed 0/8 false rewards, zero invalid packets and zero inconclusive evaluations. The paired arm differences were zero. This is a null result on eight authored finite inputs, not a measured improvement. [Protocol and evidence identities](MODEL_COMPARISON.md). Invalid packets remain in the task-success denominator; verifier failures remain inconclusive. No favorable effect is assumed.

The output tasks measure finite answer artifacts. They do not establish general program synthesis, repository-scale coding, security against unseen attack families or external benchmark performance. Three seeds and eight authored audit inputs also provide weak uncertainty information. Do not use these results as a hiring or deployment guarantee.

## Execution boundary

Sol runs trusted inference and training code. Model completions are transferred as bounded file packets. Generated candidate code executes only in the supported Mac Docker path. Hidden audits never supply the training reward. The trusted host, evidence store, Docker daemon and pinned model/image provenance remain assumptions.

The model is suitable for bounded research with inspected evidence. AutoSeal is not a public arbitrary-code service or a production security boundary. See [architecture](ARCHITECTURE.md), [calibration](SFT_CALIBRATION.md) and [measured results](RESULTS.md).
