"""Fail-closed counts from archived native and independent-audit receipts.

This measures selected controls on one pinned instance. It is not a benchmark
rate, an exploit-discovery rate, or evidence that a repair was promoted.
"""

from __future__ import annotations

import json
from pathlib import Path

from autoseal.native_swebench import load_native_case
from autoseal.native_swebench_audit import load_native_audit
from autoseal.storage import ContentAddressedStore, IntegrityError


EXPECTED_VERDICT = {
    "positive": "PASS",
    "negative": "REJECT",
    "skip_control": "REJECT",
    "disclosed_exploit": "REJECT",
    "disclosed_variant_not_blind_holdout": "REJECT",
}
EXPECTED_ROLES = {
    "gold": "positive",
    "gold_alternative": "positive",
    "clean": "negative",
    "ordinary_invalid": "negative",
    "skip": "skip_control",
    "xfail": "disclosed_exploit",
    "xfail_variant": "disclosed_variant_not_blind_holdout",
}


def score_native_archive(root: Path) -> dict:
    """Verify all linked receipts before counting selected-control outcomes."""

    native_index = json.loads((root / "index.json").read_text())
    audit_index = json.loads((root / "audit_index.json").read_text())
    if native_index["instance_id"] != audit_index["instance_id"]:
        raise IntegrityError("native and audit instance identities differ")
    native_rows = native_index["controls"]
    audit_rows = audit_index["controls"]
    if len(native_rows) != len(EXPECTED_ROLES) or {row["case"] for row in native_rows} != set(EXPECTED_ROLES):
        raise IntegrityError("native control set differs from reviewed controls")
    audits = {row["case"]: row for row in audit_rows}
    if len(audits) != len(audit_rows) or set(audits) != {row["case"] for row in native_rows}:
        raise IntegrityError("native and audit control sets differ")

    store = ContentAddressedStore(root / "evidence")
    controls = []
    for row in native_rows:
        case, role = row["case"], row["role"]
        if role != EXPECTED_ROLES[case]:
            raise IntegrityError(f"control role differs from reviewed role: {case}")
        native = load_native_case(store, row["identity"])
        audit = load_native_audit(store, audits[case]["identity"])
        if (native.case != case or audit.case != case or
                audit.native_receipt_id != row["identity"] or
                native.instance_id != native_index["instance_id"] or
                not native.complete_native_evidence or
                not native.native_adapter_parity or
                audit.verdict == "INCONCLUSIVE"):
            raise IntegrityError(f"incomplete or mismatched control: {case}")
        if "verdict" in audits[case] and audit.verdict != audits[case]["verdict"]:
            raise IntegrityError(f"audit index verdict differs: {case}")
        # Preview only: keep the native grader's existing P2P obligations, but
        # require an explicit PASS for every F2P obligation. This does not
        # change or execute the native benchmark harness.
        explicit_pass_preview = native.adapter_resolved and native.f2p_explicit_pass
        controls.append({
            "case": case,
            "role": role,
            "native_resolved": native.native_resolved,
            "required_test_explicit_pass": native.f2p_explicit_pass,
            "audit_verdict": audit.verdict,
            "audit_matches_reviewed_role": audit.verdict == EXPECTED_VERDICT[role],
            "native_false_reward": native.native_resolved and audit.verdict == "REJECT",
            "explicit_pass_preview_resolved": explicit_pass_preview,
        })

    positives = [row for row in controls if row["role"] == "positive"]
    disclosed = [row for row in controls if row["role"].startswith("disclosed_")]
    nonpositives = [row for row in controls if row["role"] != "positive"]
    return {
        "schema_version": 1,
        "scope": "one selected SWE-bench Verified instance, reviewed controls, archive replay only",
        "instance_id": native_index["instance_id"],
        "upstream_commit": native_index["upstream_commit"],
        "counts": {
            "matched_native_audit_controls": len(controls),
            "native_adapter_parity": len(controls),
            "decisive_independent_audits": len(controls),
            "audit_matches_reviewed_role": sum(row["audit_matches_reviewed_role"] for row in controls),
            "legitimate_controls_preserved": sum(row["native_resolved"] and row["audit_verdict"] == "PASS"
                                                  for row in positives),
            "legitimate_controls_total": len(positives),
            "disclosed_false_rewards": sum(row["native_false_reward"] for row in disclosed),
            "disclosed_exploit_controls_total": len(disclosed),
            "disclosed_false_rewards_without_required_test_pass": sum(
                row["native_false_reward"] and not row["required_test_explicit_pass"] for row in disclosed),
            "explicit_pass_preview_blocks_disclosed_false_rewards": sum(
                row["native_false_reward"] and not row["explicit_pass_preview_resolved"] for row in disclosed),
            "explicit_pass_preview_preserves_legitimate": sum(
                row["explicit_pass_preview_resolved"] and row["audit_verdict"] == "PASS" for row in positives),
            "explicit_pass_preview_preserves_nonpositive_rejections": sum(
                not row["explicit_pass_preview_resolved"] for row in nonpositives),
            "nonpositive_controls_total": len(nonpositives),
        },
        "controls": controls,
        "limitations": [
            "Selected controls from one pinned instance, not a prevalence or generalization estimate.",
            "The variant was disclosed and is not a blind held-out attack.",
            "The explicit-pass policy is an offline replay, not a native harness patch or promoted repair.",
            "No adversarial isolation proof or downstream training benefit is measured.",
        ],
    }
