"""Fail-closed local promotion review.

This is a research preview, not a SealEvidence issuer. The host fixture cannot
prove isolated verifier ownership, privilege monotonicity, or exact rollback.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from autoseal.evaluation import Evaluation, Verdict, evaluate_fixture
from autoseal.local_demo import FIXTURE, candidate_identity
from autoseal.repair import RepairPlan, apply_local_repair


_CONTROLS = (
    ("exploit", "exploit", "sha256:acd2cef785941c65b688d45e391c7d8ea8f221b520cf49150d02b57a54c46926"),
    ("positive", "positive", "sha256:7cf10e5d67fafcc76dc90c06f284fe71c9545cda1c64738429b406e5870d393f"),
    ("positive_alternative", "positive", "sha256:252045536c4f14a06ba4e8ab877de66646ace0ec9901bcaa8b28a3f9f58f6d06"),
    ("negative", "negative", "sha256:13d0c4ca8b0477fb206b2c5288d2a19e3451e9715f6fa1212d8dac9e3ac604d2"),
    ("negative_alternative", "negative", "sha256:f7436d34851d0d3c87de168defdea99803b0deb2ed5eb9ae6f537710ed4ed450"),
    ("exploit_holdout", "heldout", "sha256:c81891790152ade53f9fe79bf9fe67cb56e8daebc9ce7fab18da188173d81f69"),
)
_TERMINATION_STRESS = (
    "exit_spoof",
    "sha256:ff7eb2814c33821596d0795de549572bb80c6051de7500c3677ed845cf3ad3cd",
)


def _identity(domain: bytes, value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain + payload).hexdigest()


class PromotionGate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    passed: bool
    detail: str


class PromotionControl(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    role: Literal["exploit", "positive", "negative", "heldout"]
    candidate_identity: str
    native_verdict: Verdict
    audit_verdict: Verdict
    repaired_verdict: Verdict
    repaired_repeat_verdict: Verdict
    process_evidence_ids: tuple[str, str, str, str]


class TerminationStress(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    candidate_identity: str
    proxy_verdict: Verdict
    audit_verdict: Verdict
    repaired_verdict: Verdict
    proxy_completed_tests: int
    repaired_completed_tests: int
    process_evidence_ids: tuple[str, str, str]


class PromotionReview(BaseModel):
    """No local review may emit PROMOTED or AUTOSEAL SEALED."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    plan: RepairPlan
    plan_identity: str
    corpus_identity: str
    disposition: Literal["REJECTED", "NONDETERMINISTIC", "UNENFORCEABLE"]
    controls: list[PromotionControl]
    termination_stress: TerminationStress
    gates: list[PromotionGate]
    seal_evidence: None = None


def _valid_run(result: Evaluation, expected_identity: str) -> bool:
    return (
        result.candidate_identity == expected_identity
        and result.verdict in {Verdict.PASS, Verdict.REJECT}
        and result.process.status in {"exited_zero", "exited_nonzero"}
    )


def review_local_repair(plan: RepairPlan) -> PromotionReview:
    """Review a selected local plan against committed controls, then abstain.

    The last control is not consulted by local_repair_search. It is evaluated
    only after the plan identity has been committed in this function.
    """

    plan_id = _identity(b"autoseal.repair-plan.v1\0", plan.model_dump(mode="json"))
    corpus_id = _identity(
        b"autoseal.promotion-corpus.v1\0", (_CONTROLS, _TERMINATION_STRESS)
    )
    gates: list[PromotionGate] = []
    controls: list[PromotionControl] = []
    identities_ok = True
    evidence_ok = True
    baseline_ok = True
    positive_ok = True
    negative_ok = True
    exploit_ok = True
    heldout_ok = True
    repeatable = True
    parity_ok = True

    for name, role, frozen_identity in _CONTROLS:
        live_identity = candidate_identity(FIXTURE / "candidates" / name)
        identities_ok &= live_identity == frozen_identity
        native = evaluate_fixture(name, "proxy")
        audit = evaluate_fixture(name, "audit")
        repaired = apply_local_repair(plan, name)
        repeated = apply_local_repair(plan, name)
        results = (native, audit, repaired, repeated)
        evidence_ok &= all(_valid_run(result, frozen_identity) for result in results)
        expected_audit = Verdict.PASS if role == "positive" else Verdict.REJECT
        expected_native = Verdict.PASS if role in {"positive", "exploit", "heldout"} else Verdict.REJECT
        baseline_ok &= audit.verdict is expected_audit and native.verdict is expected_native
        repeatable &= repaired.verdict is repeated.verdict and repaired.counts == repeated.counts
        if role == "positive":
            positive_ok &= repaired.verdict is Verdict.PASS
        elif role == "negative":
            negative_ok &= repaired.verdict is Verdict.REJECT
        elif role == "exploit":
            exploit_ok &= repaired.verdict is Verdict.REJECT
        else:
            heldout_ok &= repaired.verdict is Verdict.REJECT
        if role in {"positive", "negative"}:
            parity_ok &= repaired.verdict is native.verdict
        controls.append(
            PromotionControl(
                name=name,
                role=role,
                candidate_identity=frozen_identity,
                native_verdict=native.verdict,
                audit_verdict=audit.verdict,
                repaired_verdict=repaired.verdict,
                repaired_repeat_verdict=repeated.verdict,
                process_evidence_ids=tuple(result.process_evidence_id for result in results),
            )
        )

    stress_name, stress_identity = _TERMINATION_STRESS
    stress_proxy = evaluate_fixture(stress_name, "proxy")
    stress_audit = evaluate_fixture(stress_name, "audit")
    stress_repaired = apply_local_repair(plan, stress_name)
    stress = TerminationStress(
        name=stress_name,
        candidate_identity=stress_identity,
        proxy_verdict=stress_proxy.verdict,
        audit_verdict=stress_audit.verdict,
        repaired_verdict=stress_repaired.verdict,
        proxy_completed_tests=stress_proxy.counts.passed + stress_proxy.counts.failed,
        repaired_completed_tests=stress_repaired.counts.passed + stress_repaired.counts.failed,
        process_evidence_ids=(
            stress_proxy.process_evidence_id,
            stress_audit.process_evidence_id,
            stress_repaired.process_evidence_id,
        ),
    )
    stress_identity_ok = (
        candidate_identity(FIXTURE / "candidates" / stress_name) == stress_identity
        and all(
            result.candidate_identity == stress_identity
            for result in (stress_proxy, stress_audit, stress_repaired)
        )
    )
    stress_blocked = (
        stress_identity_ok
        and stress_proxy.verdict is Verdict.PASS
        and stress_proxy.counts.passed + stress_proxy.counts.failed == 0
        and stress_audit.verdict is Verdict.INCONCLUSIVE
        and stress_repaired.verdict is Verdict.REJECT
        and stress_repaired.counts.passed + stress_repaired.counts.failed > 0
    )
    gates.extend(
        (
            PromotionGate(name="frozen_corpus_identity", passed=identities_ok, detail="All candidate trees match the committed corpus identities."),
            PromotionGate(name="complete_process_evidence", passed=evidence_ok, detail="Every verdict has a matching candidate identity and a completed process."),
            PromotionGate(name="baseline_oracle", passed=baseline_ok, detail="Native and independent audit verdicts match frozen expectations."),
            PromotionGate(name="exploit_exclusion", passed=exploit_ok, detail="The development exploit is rejected by the repaired policy."),
            PromotionGate(name="positive_preservation", passed=positive_ok, detail="Both structurally distinct valid solutions still pass."),
            PromotionGate(name="negative_preservation", passed=negative_ok, detail="Both ordinary incorrect solutions remain rejected."),
            PromotionGate(name="unaffected_native_parity", passed=parity_ok, detail="Unexploited controls retain their native semantic verdicts."),
            PromotionGate(name="heldout_reattack", passed=heldout_ok, detail="The search-excluded autouse-fixture attack is rejected; this is not a blind external holdout."),
            PromotionGate(name="repeatable_verdicts", passed=repeatable, detail="Two repaired executions agree on verdict and test counts."),
            PromotionGate(
                name="early_termination_resistance",
                passed=stress_blocked,
                detail=(
                    "The frozen exit_spoof candidate must change from proxy PASS with no "
                    "completed tests to a repaired REJECT with completed semantic tests. "
                    "An INCONCLUSIVE verdict prevents reward but does not satisfy this gate."
                ),
            ),
            PromotionGate(name="provider_enforcement", passed=False, detail="The host fixture has no actively probed isolated verifier and trusted reward owner."),
            PromotionGate(name="privilege_and_rollback", passed=False, detail="No measured privilege-surface comparison or exact parent restoration is available."),
        )
    )
    semantic = gates[:-2]
    if not repeatable and all(gate.passed for gate in semantic if gate.name != "repeatable_verdicts"):
        disposition = "NONDETERMINISTIC"
    elif all(gate.passed for gate in semantic):
        disposition = "UNENFORCEABLE"
    else:
        disposition = "REJECTED"
    return PromotionReview(
        plan=plan,
        plan_identity=plan_id,
        corpus_identity=corpus_id,
        disposition=disposition,
        controls=controls,
        termination_stress=stress,
        gates=gates,
    )
