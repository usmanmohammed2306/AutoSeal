"""Validation and identity must survive serialization and reject bad states."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from autoseal.evidence import CommandEvidence, evidence_id, read_evidence
from autoseal.execution import run_command


def _successful_result() -> dict[str, object]:
    return {
        "command": ["python", "-c", "print('hi')"],
        "status": "exited_zero",
        "exit_code": 0,
        "stdout": "hi\n",
        "stderr": "",
        "stdout_truncated": False,
        "stderr_truncated": False,
        "error_message": None,
        "elapsed_seconds": 0.15,
        "timeout_seconds": None,
    }


def test_equivalent_map_order_and_unicode_share_identity(tmp_path: Path) -> None:
    fields = _successful_result()
    fields["stdout"] = "café\n"
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(json.dumps(fields, ensure_ascii=False), encoding="utf-8")
    second.write_text(json.dumps(dict(reversed(list(fields.items()))), ensure_ascii=True, indent=2), encoding="utf-8")

    assert evidence_id(read_evidence(first)) == evidence_id(read_evidence(second))


def test_semantic_change_changes_identity() -> None:
    fields = _successful_result()
    baseline = evidence_id(CommandEvidence.model_validate(fields))
    fields["stdout"] = "changed\n"

    assert evidence_id(CommandEvidence.model_validate(fields)) != baseline


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"exit_code": None}, "exited_zero"),
        ({"status": "launch_error"}, "launch_error"),
        ({"status": "timeout", "exit_code": None}, "timeout requires"),
        ({"elapsed_seconds": float("nan")}, "finite"),
        ({"elapsed_seconds": float("inf")}, "finite"),
        ({"unexpected": "extra"}, "Extra inputs"),
    ],
)
def test_invalid_result_is_rejected(change: dict[str, object], message: str) -> None:
    fields = _successful_result()
    fields.update(change)

    with pytest.raises(ValidationError, match=message):
        CommandEvidence.model_validate(fields)


def test_ambiguous_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"status":"exited_zero","status":"timeout"}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate JSON key"):
        read_evidence(path)


def test_runner_result_validates() -> None:
    result = run_command(["/definitely/missing/autoseal-command"])
    evidence = CommandEvidence.model_validate(result.to_dict())

    assert evidence.status == "launch_error"
    assert evidence_id(evidence).startswith("sha256:")
