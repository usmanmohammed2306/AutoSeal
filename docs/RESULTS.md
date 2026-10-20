# Measured results

AutoSeal's current results concern deliberately selected controls and local research runs. The public source provides runnable synthetic fixtures and the code used to inspect them. Original machine-specific run archives remain local. The counts below describe previously saved evidence, not a new run performed when this page was written.

## One native evaluator case

On October 7, 2026, seven reviewed controls for `pytest-dev__pytest-7982` were evaluated through SWE-bench's native harness and a separate behavioral audit. The harness revision was `02e7a74ffd0b707aab73d203fe87bdc7c76afc8e`.

| Controls | Native resolution | Separate audit |
|---|---|---|
| `gold`, `gold_alternative` | Both resolved | Both PASS |
| `clean`, `ordinary_invalid`, `skip` | All unresolved | All REJECT |
| `xfail`, `xfail_variant` | Both resolved | Both REJECT |

The two xfail controls marked the required regression test as an expected failure without executing it. The grader counted that status as success. The separate audit checked actual directory-symlink traversal and recursion behavior after applying the implementation patch without candidate-controlled test hooks. The full patch identity and its audit projection were recorded separately.

All seven native reports matched the pinned adapter's interpretation. An October 10 offline policy preview required explicit passage of the regression test. It rejected the two disclosed false rewards, retained both valid passes, and retained all five nonpositive rejections. That preview reinterprets saved output; it is not a promoted repair deployed into the native harness.

The original discovery belongs to [cero753, SWE-bench issue 654](https://github.com/SWE-bench/SWE-bench/issues/654). AutoSeal reproduces and investigates that disclosed mechanism. The variant was known in advance. Seven controls on one task do not establish exploit prevalence or generalization. The native baseline used the upstream harness's root, `SYS_ADMIN`, and default networking settings; it is not a hostile-code isolation demonstration.

## Training plumbing and negative results

Trusted model inference and training ran on ASU Sol; candidate evaluation ran in Mac Docker. A one-step LoRA SFT run demonstrated checkpoint creation. Three successive paired GRPO pilots each used three seeds per arm and two training steps, but all lacked within-batch reward variance. Their outputs were respectively malformed, uniformly correct, or uniformly unrewarded. They do not establish a learning effect.

A later one-seed diagnostic pair produced nonconstant rewards and a nonzero gradient. Both arms generated the same completions and ended with the same adapter digest, with no sampled evaluator exploit. A scripted valid/invalid/exploit triad subsequently received vulnerable rewards `[1, 0, 1]` and sealed rewards `[1, 0, 0]`. This demonstrates reward discrimination for selected fixture outputs, not a model-training improvement.

## Scope of the implementation

The CLI, local fixtures, Docker runtime, evidence store, persisted API/worker path, Studio, and training drivers are implemented. Enforced repair promotion, diversified external-case evaluation, and the frozen multi-seed efficacy study remain open. No benchmark-wide reduction or production security guarantee is claimed.

Research scripts use AI coding assistance. Reviewed synthetic controls, disclosed exploit variants, public gold patches, and post-fix-inspection audits are identified in their case documentation; they must not be presented as blind model discoveries.
