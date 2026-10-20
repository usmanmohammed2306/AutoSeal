"""Container-backed execution for the checked-in benign Pytest fixture.

This is an integration boundary, not a claim that a local Docker daemon is an
adequate host for arbitrary hostile agent code. The user-selected deployment
is Mac Docker Desktop for scoped research, with no public untrusted-code API.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

from autoseal.execution import CommandResult, CommandStatus, run_command
from autoseal.local_demo import ArtifactProjection, FIXTURE, _counts, candidate_identity
from autoseal.projection import project_candidate_artifacts


DEFAULT_IMAGE = "autoseal-fixture:local"


@dataclass(frozen=True)
class DockerFixtureResult:
    candidate: str
    channel: str
    candidate_identity: str
    image_identity: str
    copied_files: tuple[str, ...]
    verdict: str
    counts: dict[str, int]
    process: CommandResult

    def to_dict(self) -> dict:
        return {
            "candidate": self.candidate,
            "channel": self.channel,
            "candidate_identity": self.candidate_identity,
            "image_identity": self.image_identity,
            "copied_files": list(self.copied_files),
            "verdict": self.verdict,
            "counts": self.counts,
            "process": self.process.to_dict(),
        }


def image_identity(image: str) -> str:
    completed = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    identity = completed.stdout.strip()
    if completed.returncode != 0 or not identity.startswith("sha256:"):
        raise RuntimeError(f"Docker image unavailable: {completed.stderr.strip()}")
    return identity


def run_fixture_in_docker(
    candidate_name: str,
    channel: str,
    *,
    image: str = DEFAULT_IMAGE,
    timeout_seconds: float = 15,
) -> DockerFixtureResult:
    if candidate_name not in {
        "positive", "positive_alternative", "negative", "negative_alternative",
        "exploit", "exploit_variant", "exit_spoof",
    }:
        raise ValueError("unknown checked-in fixture")
    if channel not in {"proxy", "audit", "sealed"}:
        raise ValueError("unknown evaluator channel")
    candidate = FIXTURE / "candidates" / candidate_name
    candidate_digest = candidate_identity(candidate)
    with tempfile.TemporaryDirectory(prefix="autoseal-docker-") as directory:
        workspace = Path(directory) / "workspace"
        shutil.copytree(FIXTURE / "verifier", workspace)
        if channel == "proxy":
            shutil.copytree(candidate, workspace, dirs_exist_ok=True)
        elif channel == "audit":
            shutil.copy2(candidate / "solution.py", workspace / "solution.py")
        else:
            projection = ArtifactProjection()
            project_candidate_artifacts(candidate, workspace, projection.allowed_files)
        return run_workspace_in_docker(
            workspace,
            candidate_name=candidate_name,
            candidate_digest=candidate_digest,
            channel=channel,
            image=image,
            timeout_seconds=timeout_seconds,
        )


def run_workspace_in_docker(
    workspace: Path,
    *,
    candidate_name: str,
    candidate_digest: str,
    channel: str,
    image: str = DEFAULT_IMAGE,
    timeout_seconds: float = 15,
) -> DockerFixtureResult:
    """Run an existing local workspace as a read-only verifier input."""

    if channel not in {"proxy", "audit", "sealed"}:
        raise ValueError("unknown evaluator channel")
    image_digest = image_identity(image)
    container_name = "autoseal-fixture-" + uuid.uuid4().hex
    copied = tuple(
        sorted(str(path.relative_to(workspace)) for path in workspace.rglob("*") if path.is_file())
    )
    command = [
        "docker", "run", "--rm", "--name", container_name,
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "128",
        "--memory", "512m", "--cpus", "1", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
        "--mount", f"type=bind,src={workspace},dst=/workspace,readonly",
        "--workdir", "/workspace", image_digest,
    ]
    try:
        process = run_command(
            command, timeout_seconds=timeout_seconds, max_output_bytes=32 * 1024
        )
    finally:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True, check=False, timeout=10,
        )
    counts = _counts(process.stdout)
    if process.status is CommandStatus.EXITED_ZERO:
        if channel in {"audit", "sealed"} and (counts["passed"] != 7 or counts["skipped"]):
            verdict = "INCONCLUSIVE"
        else:
            verdict = "PASS"
    elif process.status is CommandStatus.EXITED_NONZERO and counts["failed"] > 0:
        verdict = "REJECT"
    elif process.status in {CommandStatus.TIMEOUT, CommandStatus.LAUNCH_ERROR}:
        verdict = "INFRASTRUCTURE_FAILURE"
    else:
        verdict = "VERIFIER_FAILURE"
    return DockerFixtureResult(
        candidate=candidate_name,
        channel=channel,
        candidate_identity=candidate_digest,
        image_identity=image_digest,
        copied_files=copied,
        verdict=verdict,
        counts=counts,
        process=process,
    )
