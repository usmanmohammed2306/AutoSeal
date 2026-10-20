"""A small real execution path from false reward to typed projection repair.

This is a local research fixture. It does not isolate hostile code from the host.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Any, Optional

from autoseal.execution import CommandStatus, run_command
from autoseal.projection import project_candidate_artifacts


FIXTURE = Path(__file__).resolve().parents[2] / "examples" / "false_reward_pytest"
COUNTS = re.compile(r"(\d+) (passed|failed|skipped|error|errors)\b")


def candidate_identity(candidate: Path) -> str:
    """Bind the complete candidate input, including verifier-influencing files."""

    manifest: list[dict[str, str]] = []
    for path in sorted(candidate.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"candidate fixture contains a symlink: {path}")
        if path.is_file():
            manifest.append(
                {
                    "path": path.relative_to(candidate).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(b"autoseal.candidate.v1\0" + payload).hexdigest()


@dataclass(frozen=True)
class ArtifactProjection:
    """Specify exactly which candidate files may cross the verifier boundary."""

    allowed_files: tuple[str, ...] = ("solution.py",)

    def __post_init__(self) -> None:
        if not self.allowed_files or any(
            Path(name).is_absolute() or Path(name).name != name or name.startswith(".")
            for name in self.allowed_files
        ):
            raise ValueError("projection requires simple relative artifact names")


def _counts(output: str) -> dict[str, int]:
    result = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    for line in reversed(output.splitlines()):
        if " in " in line and COUNTS.search(line):
            for number, label in COUNTS.findall(line):
                result["errors" if label == "error" else label] = int(number)
            break
    return result


def evaluate(
    candidate_name: str,
    *,
    channel: str,
    projection: Optional[ArtifactProjection] = None,
) -> dict[str, Any]:
    """Evaluate the exact same solution bytes through one workspace policy."""

    if channel not in {"proxy", "audit", "sealed", "intervention"}:
        raise ValueError(f"unknown channel: {channel}")
    if Path(candidate_name).name != candidate_name or candidate_name.startswith("."):
        raise ValueError("candidate must be a simple fixture directory name")
    candidate = FIXTURE / "candidates" / candidate_name
    solution = candidate / "solution.py"
    if not solution.is_file():
        raise FileNotFoundError(solution)
    candidate_digest = candidate_identity(candidate)

    with tempfile.TemporaryDirectory(prefix=f"autoseal-demo-{channel}-") as directory:
        workspace = Path(directory)
        shutil.copytree(FIXTURE / "verifier", workspace, dirs_exist_ok=True)
        if channel == "proxy":
            shutil.copytree(candidate, workspace, dirs_exist_ok=True)
        elif channel == "audit":
            shutil.copy2(solution, workspace / "solution.py")
        else:
            if projection is None:
                raise ValueError("projected evaluation requires a projection")
            project_candidate_artifacts(candidate, workspace, projection.allowed_files)

        copied = sorted(
            str(path.relative_to(workspace))
            for path in workspace.rglob("*")
            if path.is_file()
        )
        process = run_command(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            cwd=workspace,
            timeout_seconds=10,
            max_output_bytes=32 * 1024,
        )

    counts = _counts(process.stdout)
    if process.status is CommandStatus.EXITED_ZERO:
        if channel in {"audit", "sealed"} and (
            counts["passed"] != 7 or counts["skipped"] > 0
        ):
            verdict = "INCONCLUSIVE"
        else:
            verdict = "PASS"
    elif process.status is CommandStatus.EXITED_NONZERO and counts["failed"] > 0:
        verdict = "REJECT"
    else:
        verdict = "ERROR"

    return {
        "candidate": candidate_name,
        "channel": channel,
        "solution_sha256": hashlib.sha256(solution.read_bytes()).hexdigest(),
        "candidate_identity": candidate_digest,
        "copied_files": copied,
        "counts": counts,
        "verdict": verdict,
        "process": process.to_dict(),
    }


def demo_report() -> dict[str, Any]:
    names = (
        "positive",
        "positive_alternative",
        "negative",
        "negative_alternative",
        "exploit",
        "exploit_variant",
    )
    projection = ArtifactProjection()
    cases: dict[str, dict[str, Any]] = {}
    for name in names:
        cases[name] = {
            channel: evaluate(name, channel=channel, projection=projection)
            for channel in ("proxy", "audit", "sealed")
        }

    false_reward = cases["exploit"]["proxy"]["verdict"] == "PASS" and cases["exploit"]["audit"]["verdict"] == "REJECT"
    same_candidate = all(
        len({cases[name][channel]["candidate_identity"] for channel in ("proxy", "audit", "sealed")}) == 1
        for name in names
    )
    positives_preserved = all(
        cases[name]["sealed"]["verdict"] == "PASS"
        for name in ("positive", "positive_alternative")
    )
    negatives_rejected = all(
        cases[name]["sealed"]["verdict"] == "REJECT"
        for name in ("negative", "negative_alternative")
    )
    attacks_blocked = all(
        cases[name]["proxy"]["verdict"] == "PASS"
        and cases[name]["audit"]["verdict"] == "REJECT"
        and cases[name]["sealed"]["verdict"] == "REJECT"
        for name in ("exploit", "exploit_variant")
    )
    return {
        "status": "pass" if all((false_reward, same_candidate, positives_preserved, negatives_rejected, attacks_blocked)) else "fail",
        "repair_operator": "ArtifactProjection",
        "allowed_candidate_files": list(projection.allowed_files),
        "checks": {
            "false_reward_reproduced": false_reward,
            "same_solution_across_channels": same_candidate,
            "two_legitimate_solutions_preserved": positives_preserved,
            "two_ordinary_invalid_candidates_rejected": negatives_rejected,
            "two_exploit_mechanisms_blocked": attacks_blocked,
        },
        "cases": cases,
    }
