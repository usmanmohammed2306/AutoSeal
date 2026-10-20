"""Validate process evidence and give it a stable, versioned identity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


DOMAIN = b"autoseal.command-result.v1\0"
ProcessStatus = Literal["exited_zero", "exited_nonzero", "launch_error", "timeout"]


class CommandEvidence(BaseModel):
    """The valid combinations of fields in one process result."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    command: list[str] = Field(min_length=1)
    status: ProcessStatus
    exit_code: Optional[int]
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    error_message: Optional[str] = None
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    timeout_seconds: Optional[float] = Field(default=None, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_state(self) -> "CommandEvidence":
        if self.status == "exited_zero" and self.exit_code != 0:
            raise ValueError("exited_zero requires exit_code 0")
        if self.status == "exited_nonzero" and (self.exit_code is None or self.exit_code == 0):
            raise ValueError("exited_nonzero requires a nonzero exit_code")
        if self.status in {"launch_error", "timeout"} and self.exit_code is not None:
            raise ValueError("launch_error and timeout require a null exit_code")
        if self.status == "launch_error":
            if not self.error_message:
                raise ValueError("launch_error requires an error_message")
            if self.stdout or self.stderr or self.stdout_truncated or self.stderr_truncated:
                raise ValueError("launch_error cannot have process output")
        elif self.error_message is not None:
            raise ValueError("only launch_error may have an error_message")
        if self.status == "timeout" and self.timeout_seconds is None:
            raise ValueError("timeout requires timeout_seconds")
        return self


def canonical_bytes(evidence: CommandEvidence) -> bytes:
    """Produce the same UTF-8 bytes for equivalent validated evidence."""

    return json.dumps(
        evidence.model_dump(mode="json"),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def evidence_id(evidence: CommandEvidence) -> str:
    return "sha256:" + hashlib.sha256(DOMAIN + canonical_bytes(evidence)).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not valid evidence: {value}")


def read_evidence(path: Path) -> CommandEvidence:
    """Reject ambiguous JSON before validating the result contract."""

    data = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_nonfinite,
    )
    return CommandEvidence.model_validate(data)
