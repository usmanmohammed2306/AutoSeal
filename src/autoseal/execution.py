"""Run one command and preserve structured process evidence."""

from dataclasses import asdict, dataclass
from enum import Enum
import math
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from typing import Any, BinaryIO, Optional, Sequence


class CommandStatus(str, Enum):
    """What happened at the operating-system process boundary."""

    EXITED_ZERO = "exited_zero"
    EXITED_NONZERO = "exited_nonzero"
    LAUNCH_ERROR = "launch_error"
    TIMEOUT = "timeout"


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
    elapsed_seconds: float = 0.0
    timeout_seconds: Optional[float] = None

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


def _signal_process_group(process: subprocess.Popen[bytes], sig: int) -> bool:
    """Signal the process group created for this command on POSIX systems."""

    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif process.poll() is None:
            process.send_signal(sig)
        else:
            return False
    except ProcessLookupError:
        return False
    return True


def _clean_process_group(
    process: subprocess.Popen[bytes], grace_seconds: float
) -> None:
    """Stop children in the original group even if their parent exited."""

    if _signal_process_group(process, signal.SIGTERM):
        # The direct child may exit before a descendant. Give the whole group
        # the grace period, then signal it again even if the parent is gone.
        deadline = time.monotonic() + grace_seconds
        try:
            process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:
            pass
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        _signal_process_group(process, signal.SIGKILL)
    process.wait()


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    max_output_bytes: int = 64 * 1024,
    timeout_seconds: Optional[float] = None,
    termination_grace_seconds: float = 0.2,
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
    if timeout_seconds is not None and (not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
        raise ValueError("timeout_seconds must be finite and positive")
    if not math.isfinite(termination_grace_seconds) or termination_grace_seconds < 0:
        raise ValueError("termination_grace_seconds must be finite and non-negative")

    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                normalized_command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=os.name == "posix",
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
                elapsed_seconds=time.monotonic() - started,
                timeout_seconds=timeout_seconds,
            )

        timed_out = False
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            _clean_process_group(process, termination_grace_seconds)

        stdout, stdout_truncated = _read_bounded(stdout_file, max_output_bytes)
        stderr, stderr_truncated = _read_bounded(stderr_file, max_output_bytes)

    if timed_out:
        status = CommandStatus.TIMEOUT
        exit_code = None
    else:
        status = (
            CommandStatus.EXITED_ZERO
            if process.returncode == 0
            else CommandStatus.EXITED_NONZERO
        )
        exit_code = process.returncode
    return CommandResult(
        command=normalized_command,
        status=status,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        elapsed_seconds=time.monotonic() - started,
        timeout_seconds=timeout_seconds,
    )
