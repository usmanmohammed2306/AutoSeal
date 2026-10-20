# SWE-Smith's historical missing-test reward bug

This is a real upstream evaluator case, not a newly discovered vulnerability in current SWE-Smith. [SWE-Smith issue 24](https://github.com/SWE-bench/SWE-smith/issues/24) reported that an RL coding agent could make tests disappear from parsed output, including by causing Pytest collection to fail. At the time, SWE-Smith's grader assumed an expected test passed if it was absent from the result map. The maintainers changed that rule in [fix commit `fd89801`](https://github.com/SWE-bench/SWE-smith/commit/fd89801ac1be6433339034710cdb7a27f87b673e).

The two files in `vendor/` are byte-for-byte copies of `swesmith/harness/grading.py` before and after that fix. Their Git blob identities are `0e66033191a1127091f26a0e2e83c6539c7606a0` and `2ada8471163de9e1e8cd70d6fe75a9954518367c`. The upstream project licenses them under MIT. Its license is included in `vendor/LICENSE`.

Run the function-level comparison:

```bash
python -m autoseal upstream-swesmith collection_failure
python -m autoseal upstream-swesmith legitimate_solution
python -m autoseal upstream-swesmith ordinary_failure
python -m pytest -q tests/integration/test_upstream_swesmith.py
```

The collection-failure case gives both graders the same expected tests and the same empty parsed result map. The historical grader reports both expected tests as successful; the repaired grader reports both as failed. A legitimate explicit-pass control remains a pass, and an explicit-failure control remains a rejection. This isolates the grader defect and shows that the upstream fix preserves these two controls.

What this proves: the pinned, original grading functions disagree exactly where the reported exploit needs them to disagree. It is a faithful function-level regression test against upstream source.

What this does not prove: AutoSeal has not reproduced the original RL agent rollout, the full SWE-Smith container harness, or any vulnerability in the current upstream release. The empty result map is a checked-in scenario matching the issue's mechanism, not a fresh upstream agent execution. The actual upstream repair was made by SWE-Smith. AutoSeal does not claim credit for inventing it. The project still needs an external native-run adapter, current exploit-bearing cases, and its own general repair and promotion evidence.
