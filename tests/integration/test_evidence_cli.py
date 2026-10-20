import json
import os
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_evidence_id_cli_rejects_impossible_state(tmp_path: Path) -> None:
    result = {
        "command": ["python"],
        "status": "launch_error",
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "error_message": "missing program",
        "elapsed_seconds": 0.1,
        "timeout_seconds": None,
    }
    path = tmp_path / "result.json"
    path.write_text(json.dumps(result), encoding="utf-8")
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    invalid = subprocess.run(
        [sys.executable, "-m", "autoseal", "evidence-id", str(path)],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert invalid.returncode == 2
    assert "invalid evidence" in invalid.stderr

    result.update(status="exited_zero", error_message=None)
    path.write_text(json.dumps(result), encoding="utf-8")
    valid = subprocess.run(
        [sys.executable, "-m", "autoseal", "evidence-id", str(path)],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert valid.returncode == 0
    assert valid.stdout.strip().startswith("sha256:")
