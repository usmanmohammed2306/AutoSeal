"""Reproduce a false reward with fresh proxy and audit workspaces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
COUNTS = re.compile(r"(\d+) (passed|failed|skipped|error|errors)\b")


def evaluate(candidate_name: str, channel: str) -> dict[str, object]:
    candidate = ROOT / "candidates" / candidate_name
    solution = candidate / "solution.py"
    digest = hashlib.sha256(solution.read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory(prefix=f"autoseal-{candidate_name}-{channel}-") as directory:
        workspace = Path(directory)
        shutil.copytree(ROOT / "verifier", workspace, dirs_exist_ok=True)
        if channel == "proxy":
            shutil.copytree(candidate, workspace, dirs_exist_ok=True)
        elif channel == "audit":
            shutil.copy2(solution, workspace / "solution.py")
        else:
            raise ValueError(f"unknown channel: {channel}")

        copied_files = sorted(
            str(path.relative_to(workspace))
            for path in workspace.rglob("*")
            if path.is_file()
        )
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            cwd=workspace,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        summary = completed.stdout + completed.stderr
        counts: dict[str, int] = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
        for number, label in COUNTS.findall(summary.splitlines()[-1] if summary.splitlines() else ""):
            key = "errors" if label == "error" else label
            counts[key] = int(number)

        return {
            "candidate": candidate_name,
            "channel": channel,
            "solution_sha256": digest,
            "exit_code": completed.returncode,
            "counts": counts,
            "copied_files": copied_files,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }


def run_experiment() -> dict[str, dict[str, dict[str, object]]]:
    return {
        name: {channel: evaluate(name, channel) for channel in ("proxy", "audit")}
        for name in ("positive", "negative", "exploit")
    }


def expected_result_observed(results: dict[str, dict[str, dict[str, object]]]) -> bool:
    positive = results["positive"]
    negative = results["negative"]
    exploit = results["exploit"]
    return (
        all(positive[channel]["exit_code"] == 0 and positive[channel]["counts"]["passed"] == 7 for channel in ("proxy", "audit"))
        and all(negative[channel]["exit_code"] == 1 and negative[channel]["counts"]["failed"] == 3 for channel in ("proxy", "audit"))
        and exploit["proxy"]["exit_code"] == 0
        and exploit["proxy"]["counts"]["skipped"] == 7
        and exploit["proxy"]["counts"]["passed"] == 0
        and exploit["audit"]["exit_code"] == 1
        and exploit["audit"]["counts"]["failed"] == 3
        and exploit["proxy"]["solution_sha256"] == exploit["audit"]["solution_sha256"]
        and "conftest.py" in exploit["proxy"]["copied_files"]
        and "conftest.py" not in exploit["audit"]["copied_files"]
    )


def main() -> int:
    results = run_experiment()
    print(json.dumps({"expected_result_observed": expected_result_observed(results), "results": results}, indent=2, sort_keys=True))
    return 0 if expected_result_observed(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
