"""Executable Stage 1 process-evidence acceptance checks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any

from pydantic import ValidationError

from autoseal.evidence import CommandEvidence, evidence_id
from autoseal.execution import CommandStatus, run_command


def process_evidence_report() -> dict[str, Any]:
    checks: dict[str, bool] = {}

    success = run_command([sys.executable, "-c", "print('ok')"])
    checks["exited_zero"] = success.status is CommandStatus.EXITED_ZERO and success.exit_code == 0
    checks["canonical_identity"] = (
        evidence_id(CommandEvidence.model_validate(success.to_dict()))
        == evidence_id(CommandEvidence.model_validate(json.loads(json.dumps(success.to_dict()))))
    )

    failure = run_command([sys.executable, "-c", "import sys; sys.exit(23)"])
    checks["exited_nonzero"] = failure.status is CommandStatus.EXITED_NONZERO and failure.exit_code == 23

    launch = run_command(["/definitely/missing/autoseal-command"])
    checks["launch_error"] = launch.status is CommandStatus.LAUNCH_ERROR and launch.exit_code is None

    bounded = run_command(
        [sys.executable, "-c", "import sys; sys.stdout.write('a'*20); sys.stderr.write('b'*20)"],
        max_output_bytes=7,
    )
    checks["output_truncation"] = (
        bounded.stdout == "a" * 7
        and bounded.stderr == "b" * 7
        and bounded.stdout_truncated
        and bounded.stderr_truncated
    )

    timeout = run_command(
        [sys.executable, "-c", "import time; print('before',flush=True); time.sleep(30)"],
        timeout_seconds=0.15,
    )
    checks["timeout_and_partial_output"] = (
        timeout.status is CommandStatus.TIMEOUT
        and timeout.exit_code is None
        and timeout.stdout == "before\n"
        and timeout.elapsed_seconds >= 0.15
    )

    impossible = success.to_dict()
    impossible["status"] = "launch_error"
    try:
        CommandEvidence.model_validate(impossible)
    except ValidationError:
        checks["invalid_state_rejected"] = True
    else:
        checks["invalid_state_rejected"] = False

    if os.name == "posix":
        with tempfile.TemporaryDirectory(prefix="autoseal-conformance-") as directory:
            marker = Path(directory) / "descendant-survived"
            child = f"import time,pathlib; time.sleep(0.6); pathlib.Path({str(marker)!r}).write_text('alive')"
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
                "print('spawned',flush=True); time.sleep(30)"
            )
            spawned = run_command(
                [sys.executable, "-c", parent],
                timeout_seconds=0.15,
                termination_grace_seconds=0.05,
            )
            time.sleep(0.65)
            checks["descendant_cleanup"] = (
                spawned.status is CommandStatus.TIMEOUT and not marker.exists()
            )
    else:
        checks["descendant_cleanup"] = False

    return {
        "stage": 1,
        "suite": "process-evidence",
        "status": "pass" if all(checks.values()) else "fail",
        "checks": checks,
    }
