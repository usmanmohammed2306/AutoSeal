"""Typed influence graph with intervention-backed causal edges.

The local graph proves a file-level effect on the proxy verdict. It does not
claim that every intermediate Pytest import or hook call was traced.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.evaluation import Verdict, compare_fixture
from autoseal.investigation import IntegrityFinding, Witness, finding_from_pair, minimize_fixture


class NodeKind(str, Enum):
    CANDIDATE_FILE = "candidate_file"
    VERIFIER = "verifier"
    VERDICT = "verdict"


class InfluenceNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: NodeKind
    label: str
    owner: Literal["candidate", "trusted"]


class InfluenceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    relation: Literal["COPY", "PRODUCES", "AFFECTS_REWARD"]
    support: Literal["OBSERVED", "INTERVENTION"]
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    explanation: str

    @model_validator(mode="after")
    def require_causal_proof(self) -> "InfluenceEdge":
        if self.relation == "AFFECTS_REWARD" and (
            self.support != "INTERVENTION" or len(self.evidence_ids) < 2
        ):
            raise ValueError("reward influence requires paired intervention evidence")
        return self


class InfluenceGraph(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    finding: IntegrityFinding
    nodes: list[InfluenceNode]
    edges: list[InfluenceEdge]
    resolution: Literal["file_level"] = "file_level"
    mechanism_status: Literal["NOT_TRACED"] = "NOT_TRACED"

    @model_validator(mode="after")
    def validate_graph(self) -> "InfluenceGraph":
        names = [node.id for node in self.nodes]
        if len(names) != len(set(names)):
            raise ValueError("duplicate graph node")
        if any(edge.source not in names or edge.target not in names for edge in self.edges):
            raise ValueError("edge references unknown node")
        if not any(edge.relation == "AFFECTS_REWARD" for edge in self.edges):
            raise ValueError("graph lacks intervention-backed reward influence")
        return self


def _paired_intervention(witness: Witness, file_name: str):
    """Find a PASS/REJECT pair differing only in one candidate file."""

    for included in witness.interventions:
        if file_name not in included.kept_files or included.proxy_verdict != "PASS":
            continue
        removed_names = tuple(name for name in included.kept_files if name != file_name)
        for excluded in witness.interventions:
            if (
                excluded.kept_files == removed_names
                and excluded.proxy_verdict == "REJECT"
                and excluded.solution_sha256 == included.solution_sha256
            ):
                return included, excluded
    return None


def fixture_influence_graph(candidate: str) -> InfluenceGraph:
    pair = compare_fixture(candidate)
    finding = finding_from_pair(pair)
    witness = minimize_fixture(candidate)
    nodes = [
        InfluenceNode(id="proxy-verifier", kind=NodeKind.VERIFIER, label="Vulnerable Pytest proxy", owner="trusted"),
        InfluenceNode(id="proxy-reward", kind=NodeKind.VERDICT, label="Proxy PASS", owner="trusted"),
        InfluenceNode(id="audit-verifier", kind=NodeKind.VERIFIER, label="Independent audit", owner="trusted"),
        InfluenceNode(id="audit-verdict", kind=NodeKind.VERDICT, label="Audit REJECT", owner="trusted"),
    ]
    edges = [
        InfluenceEdge(
            source="proxy-verifier", target="proxy-reward", relation="PRODUCES",
            support="OBSERVED", evidence_ids=(finding.proxy_evidence_id,),
            explanation="The proxy process exited zero and its policy assigned PASS.",
        ),
        InfluenceEdge(
            source="audit-verifier", target="audit-verdict", relation="PRODUCES",
            support="OBSERVED", evidence_ids=(finding.audit_evidence_id,),
            explanation="The independent audit failed tests on the same candidate identity.",
        ),
    ]
    if pair.proxy.verdict is not Verdict.PASS or pair.audit.verdict is not Verdict.REJECT:
        raise ValueError("expected confirmed false reward")
    for name in witness.essential_files:
        intervention_pair = _paired_intervention(witness, name)
        if intervention_pair is None:
            continue
        included, excluded = intervention_pair
        file_id = f"candidate:{name}"
        nodes.append(InfluenceNode(
            id=file_id, kind=NodeKind.CANDIDATE_FILE, label=name, owner="candidate",
        ))
        edges.append(InfluenceEdge(
            source=file_id, target="proxy-reward", relation="AFFECTS_REWARD",
            support="INTERVENTION",
            evidence_ids=(included.process_evidence_id, excluded.process_evidence_id),
            explanation=(
                f"Keeping {name} yields proxy PASS; removing only {name} yields REJECT "
                "while solution.py is unchanged. The internal Pytest mechanism is not traced."
            ),
        ))
    return InfluenceGraph(finding=finding, nodes=nodes, edges=edges)
