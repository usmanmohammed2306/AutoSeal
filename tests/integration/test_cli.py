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


def test_cli_reports_timeout_with_partial_output() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "autoseal",
            "run",
            "--timeout-seconds",
            "0.2",
            "--",
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(30)",
        ],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )

    evidence = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert evidence["status"] == "timeout"
    assert evidence["exit_code"] is None
    assert evidence["stdout"] == "started\n"


def test_demo_summary_shows_verdicts_without_raw_output() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "autoseal", "demo", "--summary"],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    report = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert report["status"] == "pass"
    assert report["cases"]["exploit"] == {
        "audit": "REJECT", "proxy": "PASS", "sealed": "REJECT"
    }
    assert "process" not in completed.stdout


def test_repair_plan_preview_shows_reversible_policy_without_a_seal() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "autoseal", "repair-plan-preview"],
        cwd=PROJECT_ROOT,
        env=_cli_environment(),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    report = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert report["forward_operators"] == [
        "ArtifactProjection", "VerdictOwnership", "ResultBinding"
    ]
    assert report["inverse_operators"] == list(reversed(report["forward_operators"]))
    assert report["policy_rollback_exact"] is True
    assert report["provider_capability_proven"] is False
    assert report["managed_artifact_rollback_proven"] is False
    assert report["seal_evidence"] is None
