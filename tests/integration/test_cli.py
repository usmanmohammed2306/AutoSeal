import json
import os
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _cli_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    return environment


def test_run_command_prints_json_evidence() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "autoseal",
            "run",
            "--",
            sys.executable,
            "-c",
            "print('hello from AutoSeal')",
        ],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        check=False,
    )

    evidence = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert evidence["status"] == "exited_zero"
    assert evidence["exit_code"] == 0
    assert evidence["stdout"] == "hello from AutoSeal\n"
    assert evidence["stderr"] == ""

def test_run_command_uses_requested_working_directory(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "autoseal",
            "run",
            "--cwd",
            str(tmp_path),
            "--",
            sys.executable,
            "-c",
            "from pathlib import Path; print(Path.cwd())",
        ],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        check=False,
    )

    evidence = json.loads(completed.stdout)

    assert completed.returncode == 0
    assert evidence["status"] == "exited_zero"
    assert Path(evidence["stdout"].strip()) == tmp_path


def test_run_without_a_child_command_is_rejected() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "autoseal", "run"],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 2
    assert "requires a command after --" in completed.stderr
