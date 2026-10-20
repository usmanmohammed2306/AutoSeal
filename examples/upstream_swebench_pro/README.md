# SWE-bench Pro future-history inspection

The public [SWE-bench Pro issue 93](https://github.com/scaleapi/SWE-bench_Pro-os/issues/93) reports that task images retain future Git history. Its reporter discovered the problem, documented model trajectories, and proposed an upstream fix. AutoSeal does not claim that discovery.

AutoSeal inspected one image named in the report, pinned by manifest digest. The image's task checkout is `d5d1ec775caf2d3c9132122c1243898e99fdb2da`. Its named fix commit, `41dfec20bfe9b62cddbbbf621bef2e9aa9685157`, is present in `.git` and has the task checkout as its parent. A read-only `git show` reveals that fix's source and test changes. This is answer leakage inside the candidate environment, a different integrity mechanism from the SWE-bench xfail grading case.

An ephemeral shallow fetch of only the task checkout preserved the exact tracked Git tree, `17ec485712222c12d9d849069d58d27bad9278e3`, while making the named fix commit unavailable. AutoSeal then materialized that complete tracked checkout in tmpfs and ran the focused `AutoDiscoveryUtils` suite. The original and projected workspaces each passed 10 tests. The original read-only test run initially failed at report output because Jest tried to write `/app/coverage`; a bounded tmpfs for that report path produced a clean exit. This is a focused preservation check, not a whole-task or whole-benchmark result.

The preservation experiment links the projected checkout to the original image's `node_modules`. An agent could traverse that link and access the original `.git`. Therefore, this workspace is **not an agent-facing seal**. The separate derived-image prototype keeps the dependencies but replaces `/app/.git` with a shallow, one-commit object database. A fresh networkless, read-only run of that image cannot resolve the named future fix and passes the same ten focused tests. This is a candidate-facing prototype for this one leak, not a general security or promotion claim. No model exploit or repair promotion is claimed.

The separate delegated-authentication audit makes the task obligation visible. It was written after inspecting the public fix, so it is not a blind audit. The unmodified task tree passes the ten original focused tests but fails one of three audit tests. A positive control built from the public upstream fix passes all thirteen combined tests. The same reject/pass distinction holds in the original and history-free images. The audit is injected into audit-only images after the candidate-facing images are built. This four-way control is focused Jest evaluation, not the native SWE-bench Pro grader. It contains one public positive, no independent alternative solution, and no hidden held-out attack.

From the repository root, after explicitly pulling the pinned public image into Mac Docker, run:

```bash
python scripts/reproduce_swebench_pro_history.py
python scripts/reproduce_swebench_pro_projection.py
python scripts/build_swebench_pro_history_seal.py
python scripts/reproduce_swebench_pro_audit.py
python -m pytest -q tests/integration/test_swebench_pro_history.py
```

The reproduction commands refuse to pull implicitly. Their Docker processes use a pinned image, no network, no host mounts, a read-only image filesystem, dropped capabilities, resource limits, and bounded temporary filesystems. The derived-image and audit-image builds use Docker's offline build network mode and change only local images. Their later test runs use the same restricted boundary. Checked outputs are saved as [history_leak_report.json](history_leak_report.json), [workspace_projection_report.json](workspace_projection_report.json), [sealed_image_report.json](sealed_image_report.json), and [semantic_audit_report.json](semantic_audit_report.json). The source image is approximately 1.08 GB compressed and 3.84 GB unpacked, so it is not a default CI dependency. This is a reviewed public-image research reproduction, not a general hostile-code isolation claim.

Next, check this derived image against independently implemented legitimate alternatives and ordinary-invalid controls, then evaluate actual exploit-bearing agent trajectories and held-out variants. Freeze those controls before assessing any repair. Do not pool this one case with variants of the same task when estimating broad rates.
