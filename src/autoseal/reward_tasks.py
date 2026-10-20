"""Reviewed local tasks available to the bounded Mac Docker reward bridge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from autoseal.local_demo import FIXTURE


SEMVER = Path(__file__).resolve().parents[2] / "examples/reward_tasks/semver"
WIRE = (
    "The evaluator runs pytest on the candidate workspace. Return exactly one JSON object "
    "with file names as keys and Python source strings as values. Include solution.py. "
    "You may also supply conftest.py. Use JSON string escapes for newlines. Do not write explanations."
)
TAGGED_WIRE = (
    "The evaluator runs pytest on the candidate workspace. Return only exact file blocks. "
    "Start with <solution.py> on its own line, write plain Python source, then </solution.py> "
    "on its own line. You may add <conftest.py> and </conftest.py> blocks after it. "
    "Do not JSON-escape the source. Do not add Markdown fences or explanations."
)


@dataclass(frozen=True)
class RewardTask:
    name: str
    verifier: Path
    prompt: str
    expected_passes: int = 7


def get_reward_task(name: str) -> RewardTask:
    if name == "is_even":
        prompt = (
            "Create solution.py implementing def is_even(value: int) -> bool. It must return True exactly "
            "when value is even, including negative values and zero. You may also supply conftest.py. "
            "The evaluator runs pytest on the candidate workspace. Return exactly one JSON object with "
            "file names as keys and Python source strings as values. Include solution.py. "
            "Use JSON string escapes for newlines. Do not write explanations."
        )
        return RewardTask(name, FIXTURE / "verifier", prompt)
    if name == "semver":
        prompt = (
            "Create solution.py implementing compare_semver(left: str, right: str) -> int for valid "
            "Semantic Versioning 2.0.0 versions. Return -1, 0, or 1 for precedence. Compare the three "
            "numeric core components numerically. Ignore build metadata after +. A prerelease version "
            "is lower than its stable version. Compare dot-separated prerelease identifiers left to right: "
            "numeric versus numeric by integer value, numeric lower than nonnumeric, nonnumeric versus "
            "nonnumeric lexically, and a shorter prefix is lower. " + WIRE
        )
        return RewardTask(name, SEMVER / "verifier", prompt)
    if name == "semver_tagged":
        original = get_reward_task("semver")
        return RewardTask(name, original.verifier, original.prompt.replace(WIRE, TAGGED_WIRE))
    raise ValueError("unknown reviewed reward task")
