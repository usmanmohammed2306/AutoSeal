"""Run one command and preserve structured process evidence."""

from dataclasses import asdict, dataclass
from enum import Enum
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time
from typing import Any, Optional, Sequence


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


class _BoundedOutput:
    """Drain both pipes fairly while retaining only each declared prefix."""

    def __init__(self, process, limit):
        self.limit = limit
        self.prefixes = {"stdout": bytearray(), "stderr": bytearray()}
        self.truncated = {"stdout": False, "stderr": False}
        self.selector = selectors.DefaultSelector()
        self.streams = (process.stdout, process.stderr)
        for name, stream in zip(("stdout", "stderr"), self.streams):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def drain(self, timeout):
        for key, _ in self.selector.select(timeout):
            try:
                block = os.read(key.fd, 64 * 1024)
            except BlockingIOError:
                continue
            if not block:
                self.selector.unregister(key.fileobj)
                continue
            prefix = self.prefixes[key.data]
            remaining = max(0, self.limit - len(prefix))
            prefix.extend(block[:remaining])
            self.truncated[key.data] |= len(block) > remaining

    def finish(self):
        # An escaped descendant may retain a pipe after the original group is
        # gone. Bound this final drain, close our descriptors, and mark that
        # stream incomplete rather than wait forever for an EOF.
        deadline = time.monotonic() + .2
        try:
            while self.selector.get_map() and time.monotonic() < deadline:
                self.drain(min(.01, max(0, deadline - time.monotonic())))
            for key in self.selector.get_map().values():
                self.truncated[key.data] = True
        finally:
            self.selector.close()
            for stream in self.streams:
                stream.close()
        return {name: bytes(value).decode("utf-8", errors="replace") for name, value in self.prefixes.items()}


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
    env: Optional[dict[str, str]] = None,
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
    if os.name != "posix":
        raise RuntimeError("bounded process capture requires the supported POSIX runner")

    started = time.monotonic()
    try:
        process = subprocess.Popen(
            normalized_command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            start_new_session=True,
        )
    except OSError as exc:
        return CommandResult(
            command=normalized_command, status=CommandStatus.LAUNCH_ERROR, exit_code=None,
            stdout="", stderr="", stdout_truncated=False, stderr_truncated=False,
            error_message=str(exc), elapsed_seconds=time.monotonic() - started, timeout_seconds=timeout_seconds,
        )

    timed_out = False
    output = _BoundedOutput(process, max_output_bytes)
    deadline = started + timeout_seconds if timeout_seconds is not None else None
    try:
        while process.poll() is None:
            remaining = deadline - time.monotonic() if deadline is not None else .05
            if remaining <= 0:
                timed_out = True
                break
            output.drain(min(.05, remaining))
    finally:
        try:
            _clean_process_group(process, termination_grace_seconds)
        finally:
            captured = output.finish()

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
        stdout=captured["stdout"],
        stderr=captured["stderr"],
        stdout_truncated=output.truncated["stdout"],
        stderr_truncated=output.truncated["stderr"],
        elapsed_seconds=time.monotonic() - started,
        timeout_seconds=timeout_seconds,
    )
