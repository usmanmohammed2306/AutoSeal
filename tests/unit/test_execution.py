import sys

import pytest

from autoseal.execution import CommandStatus, run_command


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
