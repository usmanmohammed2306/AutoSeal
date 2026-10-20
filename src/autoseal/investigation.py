"""Confirmed false-reward intake and file-level controlled minimization."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from autoseal.evaluation import PairedEvaluation, compare_fixture
from autoseal.evidence import CommandEvidence, evidence_id
from autoseal.local_demo import ArtifactProjection, FIXTURE, evaluate


class IntegrityFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    candidate_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    proxy_evidence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    audit_evidence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    predicate: Literal["proxy_pass_audit_reject"] = "proxy_pass_audit_reject"
    disposition: Literal["CONFIRMED"] = "CONFIRMED"


def finding_from_pair(pair: PairedEvaluation) -> IntegrityFinding:
    if pair.classification != "FALSE_REWARD":
        raise ValueError("finding requires a confirmed false reward")
    return IntegrityFinding(
        candidate_identity=pair.proxy.candidate_identity,
        proxy_evidence_id=pair.proxy.process_evidence_id,
        audit_evidence_id=pair.audit.process_evidence_id,
    )


class Intervention(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kept_files: tuple[str, ...]
    proxy_verdict: Literal["PASS", "REJECT", "INCONCLUSIVE", "ERROR"]
    process_status: str
    solution_sha256: str
    process_evidence_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class Witness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: IntegrityFinding
    candidate_name: str
    essential_files: tuple[str, ...]
    interventions: list[Intervention]
    minimal_within_file_granularity: bool
    query_count: int = Field(ge=0)


def minimize_fixture(candidate_name: str, *, max_queries: int = 20) -> Witness:
    """Find which candidate-controlled files keep this local false reward alive.

    This is a controlled file-level witness for the checked-in fixture, not a
    general source-code or trajectory minimizer.
    """

    if max_queries < 1:
        raise ValueError("max_queries must be positive")
    pair = compare_fixture(candidate_name)
    finding = finding_from_pair(pair)
    candidate = FIXTURE / "candidates" / candidate_name
    files = sorted(
        path.name for path in candidate.iterdir() if path.is_file() and path.name != "solution.py"
    )
    kept = ["solution.py", *files]
    interventions: list[Intervention] = []
    baseline_solution = pair.proxy.solution_sha256

    def probe(names: list[str]) -> bool:
        raw = evaluate(
            candidate_name,
            channel="intervention",
            projection=ArtifactProjection(tuple(names)),
        )
        interventions.append(
            Intervention(
                kept_files=tuple(names),
                proxy_verdict=raw["verdict"],
                process_status=raw["process"]["status"],
                solution_sha256=raw["solution_sha256"],
                process_evidence_id=evidence_id(CommandEvidence.model_validate(raw["process"])),
            )
        )
        return raw["verdict"] == "PASS" and raw["solution_sha256"] == baseline_solution

    if not probe(kept):
        raise ValueError("false reward did not reproduce in controlled intervention")
    for name in files:
        if len(interventions) >= max_queries:
            break
        trial = [item for item in kept if item != name]
        if probe(trial):
            kept = trial

    complete = len(interventions) >= 1 + len(files)
    for name in kept:
        if name == "solution.py":
            continue
        if len(interventions) >= max_queries:
            complete = False
            break
        if probe([item for item in kept if item != name]):
            complete = False
    return Witness(
        finding=finding,
        candidate_name=candidate_name,
        essential_files=tuple(name for name in kept if name != "solution.py"),
        interventions=interventions,
        minimal_within_file_granularity=complete,
        query_count=len(interventions),
    )
