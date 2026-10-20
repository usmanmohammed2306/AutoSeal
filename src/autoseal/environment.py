"""A resettable Docker environment for scoped local research experiments.

The managed workspace is the only host directory mounted into the container.
Snapshots cover that workspace, not arbitrary external side effects or process
memory. Docker Desktop is the user-selected research deployment, not a claim
of production-grade isolation for arbitrary publicly submitted hostile code.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Literal, Optional
import uuid

from pydantic import BaseModel, ConfigDict, model_validator

from autoseal.docker_fixture import (
    DEFAULT_IMAGE, DockerFixtureResult, image_identity, run_workspace_in_docker,
)
from autoseal.execution import CommandResult, CommandStatus, run_command
from autoseal.local_demo import FIXTURE


class EnvironmentState(str, Enum):
    NEW = "new"
    RUNNING = "running"
    FROZEN = "frozen"
    TERMINATED = "terminated"


class ToolAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["read", "write", "command"]
    path: Optional[str] = None
    content: Optional[str] = None
    command: Optional[list[str]] = None

    @model_validator(mode="after")
    def check_shape(self) -> "ToolAction":
        if self.kind == "command":
            if not self.command or self.path is not None or self.content is not None:
                raise ValueError("command action needs only a nonempty command")
        elif self.kind == "read":
            if not self.path or self.command is not None or self.content is not None:
                raise ValueError("read action needs only a path")
        elif not self.path or self.content is None or self.command is not None:
            raise ValueError("write action needs a path and content")
        return self


@dataclass(frozen=True)
class EnvironmentHandle:
    container_id: str
    image_identity: str
    revision: int


@dataclass(frozen=True)
class SnapshotRef:
    path: Path
    digest: str
    source_revision: int
    _temporary: tempfile.TemporaryDirectory[str]

    def cleanup(self) -> None:
        self._temporary.cleanup()


@dataclass(frozen=True)
class Observation:
    action: ToolAction
    process: CommandResult
    environment_state: EnvironmentState


_READ_SCRIPT = """
from pathlib import Path
import sys
root = Path('/workspace').resolve()
target = (root / sys.argv[1]).resolve()
if root not in target.parents or not target.is_file():
    raise SystemExit('invalid workspace file')
sys.stdout.write(target.read_text(encoding='utf-8'))
"""

_WRITE_SCRIPT = """
from pathlib import Path
import base64, sys
root = Path('/workspace').resolve()
target = (root / sys.argv[1]).resolve()
if root not in target.parents:
    raise SystemExit('invalid workspace file')
target.parent.mkdir(parents=True, exist_ok=True)
target.write_bytes(base64.b64decode(sys.argv[2], validate=True))
"""


class DockerAgentEnvironment:
    def __init__(
        self,
        *,
        image: str = DEFAULT_IMAGE,
        template: Path = FIXTURE / "verifier",
        command_timeout_seconds: float = 10,
        fixed_solution: Optional[str] = None,
    ) -> None:
        self.image = image
        self.template = template
        self.command_timeout_seconds = command_timeout_seconds
        self.fixed_solution = fixed_solution
        self.state = EnvironmentState.NEW
        self._temporary: Optional[tempfile.TemporaryDirectory[str]] = None
        self._workspace: Optional[Path] = None
        self._container_name: Optional[str] = None
        self._revision = 0

    @property
    def workspace(self) -> Path:
        if self._workspace is None or self.state not in {EnvironmentState.RUNNING, EnvironmentState.FROZEN}:
            raise RuntimeError("environment has no retained workspace")
        return self._workspace

    def _stop(self) -> None:
        if self._container_name is not None:
            subprocess.run(
                ["docker", "rm", "-f", self._container_name],
                capture_output=True, check=False, timeout=10,
            )
            self._container_name = None
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
        self._workspace = None

    def _start_from(self, source: Path) -> EnvironmentHandle:
        self._stop()
        self._temporary = tempfile.TemporaryDirectory(prefix="autoseal-env-")
        self._workspace = Path(self._temporary.name) / "workspace"
        shutil.copytree(source, self._workspace)
        protected_mount: list[str] = []
        if self.fixed_solution is not None:
            solution = self._workspace / "solution.py"
            if solution.is_symlink() or (solution.exists() and solution.read_text() != self.fixed_solution):
                self._stop()
                raise ValueError("fixed-solution source does not match the declared baseline")
            solution.write_text(self.fixed_solution)
            protected_mount = ["--mount", f"type=bind,src={solution},dst=/workspace/solution.py,readonly"]
        image_digest = image_identity(self.image)
        self._container_name = "autoseal-agent-" + uuid.uuid4().hex
        process = run_command(
            [
                "docker", "run", "-d", "--rm", "--name", self._container_name,
                "--entrypoint", "sleep", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", "128", "--memory", "512m", "--cpus", "1",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--mount", f"type=bind,src={self._workspace},dst=/workspace",
                *protected_mount,
                "--workdir", "/workspace", image_digest, "infinity",
            ],
            timeout_seconds=15,
        )
        if process.status is not CommandStatus.EXITED_ZERO:
            self._stop()
            self.state = EnvironmentState.TERMINATED
            raise RuntimeError(f"container start failed: {process.stderr}")
        self.state = EnvironmentState.RUNNING
        self._revision += 1
        return EnvironmentHandle(
            container_id=process.stdout.strip(),
            image_identity=image_digest,
            revision=self._revision,
        )

    def reset(self) -> EnvironmentHandle:
        return self._start_from(self.template)

    def step(self, action: ToolAction) -> Observation:
        if self.state is not EnvironmentState.RUNNING or self._container_name is None:
            raise RuntimeError("environment is not running")
        if action.kind == "read":
            command = ["python", "-c", _READ_SCRIPT, action.path or ""]
        elif action.kind == "write":
            encoded = base64.b64encode((action.content or "").encode("utf-8")).decode("ascii")
            if len(encoded) > 64 * 1024:
                raise ValueError("write action exceeds the fixture limit")
            command = ["python", "-c", _WRITE_SCRIPT, action.path or "", encoded]
        else:
            command = list(action.command or ())
        process = run_command(
            ["docker", "exec", self._container_name, *command],
            timeout_seconds=self.command_timeout_seconds,
        )
        if process.status in {CommandStatus.TIMEOUT, CommandStatus.LAUNCH_ERROR}:
            self.terminate()
        return Observation(action=action, process=process, environment_state=self.state)

    def snapshot(self) -> SnapshotRef:
        workspace = self.workspace
        temporary = tempfile.TemporaryDirectory(prefix="autoseal-snapshot-")
        snapshot_path = Path(temporary.name) / "workspace"
        shutil.copytree(workspace, snapshot_path)
        return SnapshotRef(
            path=snapshot_path,
            digest=_tree_digest(snapshot_path),
            source_revision=self._revision,
            _temporary=temporary,
        )

    def restore(self, snapshot: SnapshotRef) -> EnvironmentHandle:
        if _tree_digest(snapshot.path) != snapshot.digest:
            raise ValueError("snapshot digest mismatch")
        return self._start_from(snapshot.path)

    def extract(self, name: str = "solution.py") -> bytes:
        if name != "solution.py":
            raise ValueError("only solution.py is an approved fixture artifact")
        path = self.workspace / name
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(path)
        return path.read_bytes()

    def freeze(self) -> None:
        """Stop all container writers before snapshotting or evaluating files."""

        if self.state is EnvironmentState.FROZEN:
            return
        if self.state is not EnvironmentState.RUNNING or self._container_name is None:
            raise RuntimeError("only a running environment can be frozen")
        process = run_command(["docker", "rm", "-f", self._container_name], timeout_seconds=10)
        if process.status is not CommandStatus.EXITED_ZERO:
            raise RuntimeError("could not stop candidate writers; evaluation refused")
        self._container_name = None
        self.state = EnvironmentState.FROZEN

    def verify(self, channel: Literal["proxy", "audit", "sealed"]) -> DockerFixtureResult:
        """Verify current workspace with a fixed candidate identity."""

        self.freeze()
        source = self.workspace
        candidate_digest = _tree_digest(source)
        with tempfile.TemporaryDirectory(prefix="autoseal-agent-verify-") as directory:
            trusted = Path(directory) / "workspace"
            if channel == "proxy":
                shutil.copytree(source, trusted)
            else:
                shutil.copytree(self.template, trusted)
                shutil.copy2(source / "solution.py", trusted / "solution.py")
            return run_workspace_in_docker(
                trusted,
                candidate_name="scripted-agent",
                candidate_digest=candidate_digest,
                channel=channel,
                image=self.image,
            )

    def terminate(self) -> None:
        self._stop()
        self.state = EnvironmentState.TERMINATED


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256(b"autoseal.workspace.v1\0")
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("workspace snapshot contains a symlink")
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
    return "sha256:" + digest.hexdigest()
