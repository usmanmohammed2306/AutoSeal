"""Deterministic scripted agent using the same typed environment actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from autoseal.environment import DockerAgentEnvironment, Observation, ToolAction
from autoseal.execution import CommandStatus
from autoseal.local_demo import FIXTURE


@dataclass(frozen=True)
class AgentResult:
    observations: tuple[Observation, ...]
    stopped_reason: str


class ScriptedAgent:
    def __init__(self, actions: Sequence[ToolAction], *, max_steps: int = 20) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be positive")
        self.actions = tuple(actions)
        self.max_steps = max_steps

    def run(self, environment: DockerAgentEnvironment) -> AgentResult:
        observations: list[Observation] = []
        for index, action in enumerate(self.actions):
            if index >= self.max_steps:
                return AgentResult(tuple(observations), "STEP_LIMIT")
            observation = environment.step(action)
            observations.append(observation)
            if observation.process.status in {
                CommandStatus.TIMEOUT, CommandStatus.LAUNCH_ERROR
            }:
                return AgentResult(tuple(observations), "ENVIRONMENT_FAILURE")
        return AgentResult(tuple(observations), "SCRIPT_COMPLETE")


def fixture_agent(candidate_name: str) -> ScriptedAgent:
    if candidate_name not in {"positive", "negative", "exploit", "exploit_variant"}:
        raise ValueError("unknown scripted fixture")
    candidate = FIXTURE / "candidates" / candidate_name
    actions = [
        ToolAction(kind="write", path="solution.py", content=(candidate / "solution.py").read_text())
    ]
    if (candidate / "conftest.py").exists():
        actions.append(
            ToolAction(kind="write", path="conftest.py", content=(candidate / "conftest.py").read_text())
        )
    actions.append(ToolAction(kind="command", command=["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]))
    return ScriptedAgent(actions)
