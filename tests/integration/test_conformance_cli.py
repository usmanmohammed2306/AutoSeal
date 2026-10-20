import json
import os
from pathlib import Path
import subprocess
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_stage_one_conformance_cli() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-m", "autoseal", "conformance", "process-evidence"],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    report = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert report["status"] == "pass"
    assert all(report["checks"].values())
