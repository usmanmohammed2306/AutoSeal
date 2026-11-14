import sys
from pathlib import Path
import os
import time

import pytest

from autoseal.execution import CommandStatus, run_command


def test_explicit_child_environment_is_not_merged_with_parent(monkeypatch):
    monkeypatch.setenv("AUTOSEAL_PARENT_ONLY", "private-parent-value")
    result = run_command([sys.executable, "-c",
        "import os; print(os.environ.get('AUTOSEAL_CHILD_ONLY')); print('AUTOSEAL_PARENT_ONLY' in os.environ)"],
        env={"AUTOSEAL_CHILD_ONLY": "child-value"})
    assert result.exit_code == 0
    assert result.stdout == "child-value\nFalse\n"
    assert "private-parent-value" not in str(result.to_dict())


def test_successful_command_captures_stdout() -> None:
    result = run_command([sys.executable, "-c", "print('hello')"])

    assert result.status is CommandStatus.EXITED_ZERO
    assert result.exit_code == 0
    assert result.stdout == "hello\n"
    assert result.stderr == ""
    assert result.error_message is None


def test_nonzero_exit_remains_distinct_from_launch_error() -> None:
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys; print('failed', file=sys.stderr); sys.exit(7)",
        ]
    )

    assert result.status is CommandStatus.EXITED_NONZERO
    assert result.exit_code == 7
    assert result.stderr == "failed\n"
    assert result.error_message is None


def test_missing_executable_is_a_launch_error() -> None:
    result = run_command(["/definitely/missing/autoseal-command"])

    assert result.status is CommandStatus.LAUNCH_ERROR
    assert result.exit_code is None
    assert result.error_message is not None


@pytest.mark.parametrize(("stream", "script"), [
    ("stdout", "print('x' * 100, end='')"),
    ("stderr", "import sys; print('e' * 100, end='', file=sys.stderr)"),
])
def test_returned_output_is_bounded(stream: str, script: str) -> None:
    result = run_command(
        [sys.executable, "-c", script],
        max_output_bytes=10,
    )

    assert result.status is CommandStatus.EXITED_ZERO
    assert getattr(result, stream) == ("x" if stream == "stdout" else "e") * 10
    assert getattr(result, f"{stream}_truncated") is True


def test_empty_command_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one"):
        run_command([])


def test_negative_output_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        run_command([sys.executable], max_output_bytes=-1)


def test_timeout_keeps_output_and_separate_status() -> None:
    result = run_command(
        [
            sys.executable,
            "-c",
            "import sys,time; print('before', flush=True); print('error', file=sys.stderr, flush=True); time.sleep(30)",
        ],
        timeout_seconds=0.2,
    )

    assert result.status is CommandStatus.TIMEOUT
    assert result.exit_code is None
    assert result.stdout == "before\n"
    assert result.stderr == "error\n"
    assert result.elapsed_seconds >= 0.2
    assert result.elapsed_seconds < 3


def test_command_that_finishes_before_deadline_keeps_exit_status() -> None:
    result = run_command([sys.executable, "-c", "print('done')"], timeout_seconds=2)

    assert result.status is CommandStatus.EXITED_ZERO
    assert result.exit_code == 0
    assert result.stdout == "done\n"


@pytest.mark.parametrize("value", [0, -1, float("nan"), float("inf")])
def test_nonpositive_timeout_is_rejected(value: float) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        run_command([sys.executable], timeout_seconds=value)


@pytest.mark.skipif(os.name != "posix", reason="process-group cleanup is POSIX specific")
def test_timeout_stops_descendant_before_it_can_write(tmp_path: Path) -> None:
    marker = tmp_path / "survived.txt"
    child_script = f"import time,pathlib; time.sleep(0.8); pathlib.Path({str(marker)!r}).write_text('alive')"
    parent_script = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_script!r}]); "
        "print('spawned', flush=True); time.sleep(30)"
    )

    result = run_command(
        [sys.executable, "-c", parent_script],
        timeout_seconds=0.2,
        termination_grace_seconds=0.05,
    )
    time.sleep(0.9)

    assert result.status is CommandStatus.TIMEOUT
    assert result.stdout == "spawned\n"
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="SIGTERM test is POSIX specific")
def test_uncooperative_child_is_force_killed() -> None:
    result = run_command(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(30)",
        ],
        timeout_seconds=0.2,
        termination_grace_seconds=0.05,
    )

    assert result.status is CommandStatus.TIMEOUT
    assert result.stdout == "ready\n"
    assert result.elapsed_seconds < 3


def test_large_simultaneous_streams_drain_without_disk_spooling(monkeypatch):
    import tempfile
    def no_spool(*args, **kwargs):
        raise AssertionError('process output must not spill to an unbounded temporary file')
    monkeypatch.setattr(tempfile, 'TemporaryFile', no_spool)
    source = "import os\nfor _ in range(128):\n os.write(1,b'o'*65536); os.write(2,b'e'*65536)\n"
    result = run_command([sys.executable, '-c', source], max_output_bytes=1024, timeout_seconds=5)
    assert result.status is CommandStatus.EXITED_ZERO
    assert result.stdout == 'o' * 1024 and result.stderr == 'e' * 1024
    assert result.stdout_truncated and result.stderr_truncated


def test_zero_capture_budget_still_drains_until_exit():
    result = run_command([sys.executable, '-c', "import os; os.write(1,b'x'*100000); os.write(2,b'y'*100000)"],
                         max_output_bytes=0, timeout_seconds=2)
    assert result.status is CommandStatus.EXITED_ZERO
    assert result.stdout == result.stderr == ''
    assert result.stdout_truncated and result.stderr_truncated


def test_background_descendant_cannot_hold_capture_open():
    # This descendant stays in the original process group and is cleaned up
    # even though its direct parent exits successfully without waiting.
    source = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);print('parent done')"
    result = run_command([sys.executable, '-c', source], timeout_seconds=2, termination_grace_seconds=.05)
    assert result.status is CommandStatus.EXITED_ZERO
    assert result.stdout == 'parent done\n' and result.elapsed_seconds < 2
