# Inspect release evidence

AutoSeal's frozen release requires more than implemented features and passing unit tests. The current `release-check` command verifies supported retained archives and names the remaining proof obligations. It returns a nonzero status while V1 is incomplete. It currently cannot issue a complete V1 certificate.

Start with an empty candidate:

```json
{
  "kind": "autoseal_release_candidate",
  "schema_version": 1
}
```

Save it as `.autoseal/release-candidate.json`, then run:

```bash
python -m autoseal release-check \
  --root . \
  --manifest .autoseal/release-candidate.json
```

Exit 1 means the valid candidate is incomplete. Exit 2 means the manifest is invalid or unreadable. Neither status is a completed release. The command is read-only with respect to candidates and compute: it never launches Docker, a training job or a cloud service.

Supported references are `authored_corpus`, `native_shell`, `native_swebench_directory`, `sft_calibration` and `paired_model_study`. Digest references contain a `directory` relative to `--root` and an immutable `identity`. The paired study points to its hidden Docker evaluation in the study evidence store. The SWE-bench directory uses its existing native/audit index format. Extra fields, absolute paths, traversal, escaped archive roots and passing-boolean overrides are refused.

The authored-corpus verifier follows each individual preservation/admission receipt. It separately checks whether the complete bound runtime source inventory matches the current checkout. A historical receipt can remain valid evidence while failing current-source release admission.

Native reproduction archives remain distinct from promoted external repairs. A one-seed format calibration remains distinct from a three-seed reward comparison with hidden audits. A complete verified paired-study receipt can satisfy its named comparison gate even when the effect is null. It does not satisfy external admission, clean/nonrepairable corpus, ablation, product, security/recovery, scale, clean reproduction, AWS operation, ownership or publication obligations. Those proof protocols must be implemented and exercised before a future checker can issue V1 acceptance.

This diagnostic command exposes the remaining work. It does not waive the complete product charter or convert a plan, hand-written summary, screenshot or submitted job into completed evidence.
