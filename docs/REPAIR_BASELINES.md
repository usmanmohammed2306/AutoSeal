# Compare the repair policies fairly

The November 13 retrospective comparison uses the same six development controls from each of eight authored fixed-output tasks. Each method therefore has 48 control outcomes: 16 legitimate artifacts, 16 ordinary-invalid artifacts and 16 attack controls. The task unit is eight. These are not 48 independent benchmark tasks, new executions or model discoveries.

| Method | Valid artifacts accepted / 16 | Ordinary-invalid artifacts rejected / 16 | Attack false rewards / 16 | Inconclusive |
|---|---:|---:|---:|---:|
| Original vulnerable proxy | 16 | 16 | 16 | 0 |
| Exact minimized-file witness denylist | 16 | 16 | 8 | 0 |
| Fixed answer projection, verdict ownership and binding | 16 | 16 | 0 | 0 |
| First exploit-blocking plan, without preservation selection | 0 | 16 | 0 | 0 |
| First plan preserving one positive and rejecting the primary exploit | 16 | 16 | 0 | 0 |
| Full AutoSeal selected plan | 16 | 16 | 0 | 0 |

The preservation-free selector chose a plan that discarded the required answer. It rejected every valid artifact in this population. This shows why blocking an exploit alone is insufficient for promotion.

**The fixed strict policy tied the full method.** The one-positive selector also tied it. This small corpus provides no evidence that automatic plan selection outperforms fixed hardening, or that multiple positives were necessary to select the winner. Those claims need a population that can actually distinguish them. Optional program files are present in these controls but are not executed by their fixed-output task contract, so this is not preservation of general program behavior.

## What the comparison actually does

`scripts/compare_artifact_baselines.py` revalidates each original admission report and its linked candidate, audit, search, environment, enforcement and rollback receipts. It then selects comparable verdicts from the original development phase. Every method uses the same six controls. The two search-excluded variants are omitted because every comparator does not have matching receipts on them. Their earlier validation remains separate evidence.

The denylist is an explicit offline counterfactual: it rejects a candidate containing all the minimized non-answer witness files at their original paths with the exact bytes. Other candidates retain the original proxy verdict. It does not merely compare whole-candidate identities. This rule misses the eight development variants in this dataset. Its decisions are policy replay, not newly launched verifier executions.

The fixed policy projects `answer.json`, gives the verdict to the trusted data checker and binds the result identities. The two ablated selectors use the original frozen plan order and their declared primary-exploit/positive predicates. The full method uses the already admitted development-only winner. No held-out observation selects a plan in this comparison.

The analysis source and selector definitions are retained with the report, but the author had already seen the original outcomes. **This is retrospective development analysis**, not a preregistered final experiment. The earlier whole-artifact denylist drafts are retained locally; strengthening it to exact minimized-file matching left these aggregate outcomes unchanged.

## Recompute a retained archive

```bash
python scripts/compare_artifact_baselines.py \
  --corpus-root /absolute/path/to/retained-corpus \
  --corpus-id sha256:5a2330e3c468d957a177c18bf860357231a18525709ae864a29fa6ae64378a71 \
  --root .autoseal/development-baseline-001
```

Run it again with the same arguments plus `--check-id ORIGINAL_ANALYSIS_ID` to recompute the saved table from raw receipts. An edited summary cannot replace those receipts. The [public compact report](../examples/repair_baselines/development_summary.json) contains the original identities and denominators. The original raw stores remain separately retained; a public summary alone cannot pass the checker.

`tests/unit/test_development_baselines.py` checks denominators and inconclusive handling with synthetic rows. When the original archive is present, it also checks these real case outcomes and rejects an improved counterfeit summary. Archive-dependent checks skip explicitly when the raw data is absent.

There is no matched released separation implementation or Hacker-Fixer patch in this authored archive. Those comparators remain `UNAVAILABLE` with explicit reasons, rather than receiving a favorable approximation under another method's name. Faithful native baselines, the full frozen ablation set, fresh release experiments and diversified external cases remain required. This report does not close those gates or establish learned reward-hacking reduction.
