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

A later 7B format calibration completed 16 LoRA updates, including a verified pause at step 8 and resume to step 16. Across eight known development requests per phase, strict packets changed from 3/8 to 4/8 and independent task passes from 1/8 to 2/8. Both benign tasks pass afterward, but four outputs remain malformed. Confirmed false rewards and adherence to the six fixed-wrong-output requests both remain zero. This is insufficient syntax reliability, not reward-hacking reduction or the required multi-seed study. [Exact data, checkpoint lineage, commands and limitations](SFT_CALIBRATION.md).

A separately frozen 64-update completion-only follow-up completed a verified pause at 32 and resume to 64. Strict packets reached 5/8, task passes 2/8, and literal-null adherence 3/6; confirmed false rewards remained zero. Its baseline bytes match the earlier baseline. This changes two development settings and does not isolate either effect. Training loss became small while three packets still failed, which is why the output audit remains separate from optimizer metrics.

Two later admitted-reward preflights each completed two steps per arm with one seed and the same shared SFT adapter. The first produced two malformed packets and six rejected answers per arm. Operation-specific prompts made all eight packets valid in the second run, but all eight answers still failed. Every reward and recorded gradient norm was zero, and all four resulting adapters were byte-identical to the starting adapter. The final-study readiness guard refused the first run. A separately frozen shorter-input preflight then produced one mixed-reward group and a nonzero gradient per arm. Both resulting adapters changed but remained identical to each other, so there is still no measured sealing effect. These null results are retained separately from scripted reward checks; they do not demonstrate learning or satisfy the required final study.

Trusted model inference and training ran on ASU Sol; candidate evaluation ran in Mac Docker. A one-step LoRA SFT run demonstrated checkpoint creation. Three successive paired GRPO pilots each used three seeds per arm and two training steps, but all lacked within-batch reward variance. Their outputs were respectively malformed, uniformly correct, or uniformly unrewarded. They do not establish a learning effect.

A later one-seed diagnostic pair produced nonconstant rewards and a nonzero gradient. Both arms generated the same completions and ended with the same adapter digest, with no sampled evaluator exploit. A scripted valid/invalid/exploit triad subsequently received vulnerable rewards `[1, 0, 1]` and sealed rewards `[1, 0, 0]`. This demonstrates reward discrimination for selected fixture outputs, not a model-training improvement.

## Scope of the implementation

### November 13 repair and workflow results

The fixed-output adapter validated and admitted **eight deliberately authored seeded cases** across four proxy mechanisms and four finite output operations. Each case freezes two valid controls, two ordinary-invalid controls, an exploit, a development variant and two search-excluded variants. Three typed plans are tested on development controls. An exploit-blocking plan that drops the required output is rejected; the selected plan must pass every preservation, repeatability, capability and rollback gate before activation with `SealEvidence`.

All eight cases passed their finite gates. Three distinct sealed executions are required per control. These counts describe authored fixed-output cases, not eight external benchmarks or unprompted model discoveries. The original Python-function early-exit case remains inconclusive and unpromotable. [Workflow details and reproducible commands](REPAIR_WORKFLOWS.md).

A separate authenticated HTTP, PostgreSQL, worker and Docker check passed nine checks in 160.51 seconds. It killed its own worker, waited for natural lease expiry, reclaimed the job, removed only its own scoped containers, and completed promotion, fresh replay, exact rollback and cancellation checks. Its first attempt found an FK insert-order bug; that failure was retained and the transaction order was corrected. This is process-crash recovery on one local host, not a whole-host disaster-recovery or public deployment test.

The later complete repair/workflow regression passed **408 tests with one configured-PostgreSQL skip**. The separate disposable-PostgreSQL check passed all nine actual workflow checks rather than treating that skip as a pass. This snapshot includes the post-checkpoint audit module and task-difficulty calibration. Seven later archive-delivery boundary checks passed separately.

Saved-evidence verification also received a bounded per-traversal byte snapshot. On one warm local archive, ten alternating-order pairs returned identical results with median verification **293.40 ms uncached and 137.63 ms with snapshots (2.13x)**. New requests still recheck stored bytes. This is not candidate-execution speed, model throughput, cold-storage performance or a concurrent cloud-load result. Run `scripts/benchmark_verification.py` for a new measurement on a supplied archive.

The [disclosed shell-task case](NATIVE_SHELL_CASE.md) adds eight reviewed controls and 24 fresh Docker evaluations of unchanged native tests, a separate clean-runtime audit and projected tests. Both legitimate alternatives passed; both ordinary-invalid controls failed; four disclosed runtime mutations passed native tests but failed the clean audit and projected checks. Its dependency bootstrap is adapted on arm64. It is not an official Terminal-Bench harness score or a promoted external repair. Original reporters retain discovery credit.

The CLI, local fixtures, Docker runtime, evidence store, persisted API/worker path, Studio and training drivers are implemented. Enforced admission is now exercised on the seeded fixed-output adapter. Diversified accepted external-case repairs, the frozen multi-seed study and complete delivery/release validation remain open. No benchmark-wide reduction or production security guarantee is claimed.

Research scripts use AI coding assistance. Reviewed synthetic controls, disclosed exploit variants, public gold patches, and post-fix-inspection audits are identified in their case documentation; they must not be presented as blind model discoveries.
