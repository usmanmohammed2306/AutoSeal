"""Versioned, content-addressed trajectories for the benign Docker task pack.

Replaying this record re-executes the declared scripted actions. It checks
semantic outcomes, not byte-identical timings or container identifiers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from autoseal.agent import ScriptedAgent, fixture_agent
from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import DockerAgentEnvironment, ToolAction, _tree_digest
from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.local_demo import FIXTURE


class TrajectoryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: int = Field(ge=0)
    kind: Literal["environment_reset", "tool_observation", "artifact", "evaluation", "terminal"]
    object_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class Trajectory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    candidate: str
    fixture_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    verifier_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    image_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidate_identity: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    events: list[TrajectoryEvent]
    terminal_state: Literal["COMPLETE", "AGENT_FAILURE", "EVALUATOR_FAILURE"]
    complete_evidence: bool

    @model_validator(mode="after")
    def validate_event_stream(self) -> "Trajectory":
        if not self.events or [event.sequence for event in self.events] != list(range(len(self.events))):
            raise ValueError("trajectory sequence must be contiguous and ordered")
        kinds = [event.kind for event in self.events]
        if kinds[0] != "environment_reset" or kinds[-1] != "terminal":
            raise ValueError("trajectory requires reset first and terminal last")
        if kinds.count("terminal") != 1 or kinds.count("artifact") != 1 or kinds.count("evaluation") != 2:
            raise ValueError("trajectory requires one artifact and two evaluations")
        if self.complete_evidence != (self.terminal_state == "COMPLETE"):
            raise ValueError("only a complete terminal state may assert complete evidence")
        return self


def _append(store: ContentAddressedStore, events: list[TrajectoryEvent], kind: str, value: dict) -> None:
    events.append(TrajectoryEvent(sequence=len(events), kind=kind, object_id=store.put_json(value)))


def record_scripted_fixture(
    candidate: str, store: ContentAddressedStore, *, image: str = DEFAULT_IMAGE
) -> str:
    """Record a checked-in agent run and both verifier channels."""

    agent: ScriptedAgent = fixture_agent(candidate)
    candidate_path = FIXTURE / "candidates" / candidate
    fixture_identity = _tree_digest(candidate_path)
    verifier_identity = _tree_digest(FIXTURE / "verifier")
    environment = DockerAgentEnvironment(image=image)
    events: list[TrajectoryEvent] = []
    try:
        handle = environment.reset()
        _append(store, events, "environment_reset", {
            "image_identity": handle.image_identity,
            "verifier_identity": verifier_identity,
            "revision": handle.revision,
        })
        agent_result = agent.run(environment)
        for observation in agent_result.observations:
            _append(store, events, "tool_observation", {
                "action": observation.action.model_dump(mode="json"),
                "process": observation.process.to_dict(),
                "environment_state": observation.environment_state.value,
            })
        if agent_result.stopped_reason != "SCRIPT_COMPLETE":
            raise RuntimeError(f"agent did not complete: {agent_result.stopped_reason}")
        solution = environment.extract()
        _append(store, events, "artifact", {
            "name": "solution.py", "content_id": store.put_bytes(solution),
        })
        proxy = environment.verify("proxy")
        audit = environment.verify("audit")
        if proxy.candidate_identity != audit.candidate_identity:
            raise RuntimeError("proxy and audit did not evaluate the same candidate")
        for result in (proxy, audit):
            _append(store, events, "evaluation", result.to_dict())
        terminal_state = "COMPLETE" if proxy.verdict not in {
            "VERIFIER_FAILURE", "INFRASTRUCTURE_FAILURE"
        } and audit.verdict not in {"VERIFIER_FAILURE", "INFRASTRUCTURE_FAILURE"} else "EVALUATOR_FAILURE"
        _append(store, events, "terminal", {
            "state": terminal_state,
            "agent_stopped_reason": agent_result.stopped_reason,
        })
        record = Trajectory(
            candidate=candidate,
            fixture_identity=fixture_identity,
            verifier_identity=verifier_identity,
            image_identity=handle.image_identity,
            candidate_identity=proxy.candidate_identity,
            events=events,
            terminal_state=terminal_state,
            complete_evidence=terminal_state == "COMPLETE",
        )
        return store.put_json(record.model_dump(mode="json"))
    finally:
        environment.terminate()


def load_trajectory(store: ContentAddressedStore, identity: str) -> Trajectory:
    record = Trajectory.model_validate(store.get_json(identity))
    payloads = [store.get_json(event.object_id) for event in record.events]
    if payloads[0]["image_identity"] != record.image_identity:
        raise IntegrityError("trajectory image identity mismatch")
    if payloads[0]["verifier_identity"] != record.verifier_identity:
        raise IntegrityError("trajectory verifier identity mismatch")
    artifact = payloads[[event.kind for event in record.events].index("artifact")]
    store.get_bytes(artifact["content_id"])
    evaluations = [payload for event, payload in zip(record.events, payloads) if event.kind == "evaluation"]
    if [item["channel"] for item in evaluations] != ["proxy", "audit"]:
        raise IntegrityError("trajectory evaluation order mismatch")
    if any(item["candidate_identity"] != record.candidate_identity for item in evaluations):
        raise IntegrityError("trajectory candidate identity mismatch")
    if payloads[-1]["state"] != record.terminal_state:
        raise IntegrityError("trajectory terminal state mismatch")
    return record


def replay_scripted_fixture(store: ContentAddressedStore, identity: str) -> dict:
    """Re-execute pinned local inputs, then compare verdicts and test counts."""

    record = load_trajectory(store, identity)
    if _tree_digest(FIXTURE / "candidates" / record.candidate) != record.fixture_identity:
        raise IntegrityError("candidate fixture revision changed")
    if _tree_digest(FIXTURE / "verifier") != record.verifier_identity:
        raise IntegrityError("verifier revision changed")
    if image_identity(DEFAULT_IMAGE) != record.image_identity:
        raise IntegrityError("fixture image revision changed")
    stored = [store.get_json(event.object_id) for event in record.events if event.kind == "evaluation"]
    environment = DockerAgentEnvironment(image=DEFAULT_IMAGE)
    try:
        environment.reset()
        actions = [
            ToolAction.model_validate(store.get_json(event.object_id)["action"])
            for event in record.events if event.kind == "tool_observation"
        ]
        result = ScriptedAgent(actions).run(environment)
        if result.stopped_reason != "SCRIPT_COMPLETE":
            raise IntegrityError("replay agent did not complete")
        observed = [environment.verify("proxy"), environment.verify("audit")]
    finally:
        environment.terminate()
    comparisons = []
    for old, new in zip(stored, observed):
        comparisons.append({
            "channel": new.channel,
            "stored_verdict": old["verdict"],
            "replayed_verdict": new.verdict,
            "stored_counts": old["counts"],
            "replayed_counts": new.counts,
            "matched": old["verdict"] == new.verdict and old["counts"] == new.counts,
        })
    return {"trajectory_id": identity, "matched": all(item["matched"] for item in comparisons), "comparisons": comparisons}
