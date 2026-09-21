"""Run one command and preserve structured process evidence."""

from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
import subprocess
import tempfile
from typing import Any, BinaryIO, Optional, Sequence


class CommandStatus(str, Enum):
    """What happened at the operating-system process boundary."""

    EXITED_ZERO = "exited_zero"
    EXITED_NONZERO = "exited_nonzero"
    LAUNCH_ERROR = "launch_error"


@dataclass(frozen=True)
class CommandResult:
    """Immutable evidence from one command execution."""

    command: tuple[str, ...]
    status: CommandStatus
    exit_code: Optional[int]
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    error_message: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        result = asdict(self)
        result["status"] = self.status.value
        return result


def _read_bounded(stream: BinaryIO, limit: int) -> tuple[str, bool]:
    """Return at most ``limit`` bytes and whether additional bytes existed."""

    stream.seek(0)
    captured = stream.read(limit + 1)
    truncated = len(captured) > limit
    text = captured[:limit].decode("utf-8", errors="replace")
    return text, truncated


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    max_output_bytes: int = 64 * 1024,
) -> CommandResult:
    """Run a command without a shell and return structured process evidence.

    A zero exit code means that the process reported successful execution. It
    does not mean that the candidate solution is semantically correct.
    """

    normalized_command = tuple(str(part) for part in command)
    if not normalized_command:
        raise ValueError("command must contain at least one argument")
    if max_output_bytes < 0:
        raise ValueError("max_output_bytes must be non-negative")

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            completed = subprocess.run(
                normalized_command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
            )
        except OSError as exc:
            return CommandResult(
                command=normalized_command,
                status=CommandStatus.LAUNCH_ERROR,
                exit_code=None,
                stdout="",
                stderr="",
                stdout_truncated=False,
                stderr_truncated=False,
                error_message=str(exc),
            )

        stdout, stdout_truncated = _read_bounded(stdout_file, max_output_bytes)
        stderr, stderr_truncated = _read_bounded(stderr_file, max_output_bytes)

    status = (
        CommandStatus.EXITED_ZERO
        if completed.returncode == 0
        else CommandStatus.EXITED_NONZERO
    )
    return CommandResult(
        command=normalized_command,
        status=status,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
    )
