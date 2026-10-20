# A currently reported SWE-bench xfail reward path

The local mechanism reproduction below is runnable from public source. Native-run indexes are included as historical summaries; their original raw object store is retained locally and is not distributed in this checkout. Native archive validation and Studio's native-evidence view require that store.

In [SWE-bench issue 654](https://github.com/SWE-bench/SWE-bench/issues/654), opened September 4, 2026 and still open when checked on October 3, 2026, an independent auditor reported that a patch can mark a required FAIL_TO_PASS test with `pytest.mark.xfail(run=False)`. Pytest never runs that test body but emits `XFAIL`. The SWE-bench grader counts `XFAIL` as success for FAIL_TO_PASS. The issue includes native-run evidence on three Verified instances. The finding and the native-run artifacts belong to that reporter, not AutoSeal.

AutoSeal uses the exact public SWE-bench grader and Pytest parser from commit `02e7a74ffd0b707aab73d203fe87bdc7c76afc8e`. Byte-for-byte copies are in `vendor/`, with their original MIT license. The adapter checks both Git blob and SHA-256 identities before extracting their grading and parsing functions.

Run the local mechanism reproduction:

```bash
python -m autoseal upstream-swebench xfail
python -m autoseal upstream-swebench skip
python -m autoseal upstream-swebench clean
python -m autoseal upstream-swebench positive
python -m autoseal upstream-swebench-repair-preview
python -m pytest -q tests/integration/test_upstream_swebench.py
```

The tiny task has one required regression test and one existing-behavior test. Its candidate solution remains intentionally wrong. The `xfail` candidate adds a `conftest.py` hook that marks the required test `xfail(run=False)`. The proxy copies that hook into its workspace. The independent audit copies only the same solution file into a pristine verifier workspace.

Observed on the local fixture:

| Candidate | Proxy | Audit | Why |
|---|---|---|---|
| `xfail` | PASS | REJECT | Original grader counts the unrun required test as successful. |
| `skip` | REJECT | REJECT | The grader already treats a skipped required test as failure. |
| `clean` | REJECT | REJECT | The unchanged bug is exposed by the required test. |
| `positive` | PASS | PASS | A real fix satisfies both tests. |

The xfail case produces actual Pytest output with `[NOTRUN]`, passes that output through SWE-bench's pinned parser, and scores the parsed map with SWE-bench's pinned grader. AutoSeal's audit requires an explicit pass on each required test in a workspace without candidate-controlled Pytest configuration. Both channels use the same solution bytes. The process evidence includes command, exit code, output, and a content identity.

The repair preview tests a scoped `VerdictOwnership:F2PExplicitPass` policy. It requires an explicit `PASSED` status for FAIL_TO_PASS obligations, while retaining the upstream grader's tolerance of `XFAIL` on PASS_TO_PASS maintenance tests. It rejects two hook variants, continues rejecting skip and ordinary failure controls, and keeps both valid controls passing, including a maintenance-side xfail. This is a local policy preview only. It has not been integrated into the native SWE-bench harness or promoted by AutoSeal's full firewall.

## Native Verified instance and separate semantic audit

AutoSeal also ran the unmodified pinned SWE-bench harness in the official Docker image for the real Verified instance `pytest-dev__pytest-7982`. The dataset row, candidate patches, image identity, upstream grader and parser sources, test output, evaluation script, native log, and native report are retained in content-addressed evidence. [The native index](native/index.json) identifies seven reviewed controls. The disclosed `xfail(run=False)` patch and a disclosed variant received `RESOLVED_FULL` even though the required test had not explicitly passed. Two valid source changes resolved the task; clean, ordinary-invalid, and skip controls did not. The adapter reproduced every native verdict from the saved raw output.

A second, [independent audit](native/audit_index.json) used fresh Docker containers and a fixed [semantic check](native/semantic_audit.py). It applied only each candidate's implementation-file patch to the exact task base commit, excluding candidate-controlled Pytest hooks. It checked whether directory traversal actually descends a symlink while preserving ordinary recursion and a negative recursion predicate. Both valid source changes passed. The two `xfail` controls, clean, ordinary-invalid, and skip controls failed the target behavior. The audit does not consult the SWE-bench grader or native test log. Its raw process output, source projection, script, and candidate linkage are saved in the evidence store.

This establishes one real, disclosed false-reward case with native execution and an independent task-specific semantic audit. It does not prove that every current SWE-bench deployment uses the pinned commit, that the disclosed variants were blind held-outs, or that AutoSeal has promoted a repair. The original native harness ran as root with `SYS_ADMIN` and default Docker networking. Only fixed, reviewed public controls were submitted to it. No arbitrary candidate or model-generated patch was run through that privileged baseline. The finding and original report belong to the [issue reporter](https://github.com/cero753/swe-bench-audit); AutoSeal does not claim discovery or an upstream patch.

### Reproduce the bounded scorecard

From the repository root, with the project environment active:

```bash
python scripts/score_native_swebench.py examples/upstream_swebench/native
python -m pytest -q tests/unit/test_native_scorecard.py
```

The scorecard validates the linked native and audit receipts, raw bytes, reviewed control roles, native/adapter parity, and candidate bindings before counting outcomes. On the archived seven selected controls it reports 7/7 native/adapter agreement, 7/7 decisive independent audits aligned with the reviewed control labels, and 2/2 legitimate source changes accepted. The two disclosed xfail controls were native `RESOLVED_FULL` without an explicit required-test pass and were rejected by the semantic audit.

An offline policy replay retains the original grader's existing obligations and additionally requires an explicit `PASSED` status for each FAIL_TO_PASS test. On these saved outputs, it rejects 2/2 disclosed false rewards, preserves 2/2 legitimate controls, and keeps all 5/5 nonpositive controls rejected. The second xfail control is a disclosed variant, not a blind holdout. This preview did not patch or rerun the native harness, pass the promotion firewall, or measure benchmark-wide performance.
