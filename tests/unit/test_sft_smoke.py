from pathlib import Path
import hashlib
import json

import pytest

from autoseal.local_demo import FIXTURE
from scripts.sol.sft_smoke import load_examples


ROOT = Path(__file__).resolve().parents[2]


def test_smoke_examples_match_checked_in_valid_solutions() -> None:
    examples, digest = load_examples(
        ROOT / "examples/training_pilot/valid_solutions.jsonl"
    )
    assert digest.startswith("sha256:")
    assert len(examples) == 2
    for example, name in zip(examples, ("positive", "positive_alternative")):
        assert example["completion"] == (
            FIXTURE / "candidates" / name / "solution.py"
        ).read_text()
        assert "audit" not in example["prompt"].lower()


def test_smoke_loader_rejects_audit_fields(tmp_path: Path) -> None:
    source = tmp_path / "leaking.jsonl"
    source.write_text('{"prompt":"task","completion":"answer","audit_verdict":"PASS"}\n')
    with pytest.raises(ValueError, match="only prompt and completion"):
        load_examples(source)


def test_published_pilot_evidence_binds_local_inputs() -> None:
    evidence = json.loads(
        (ROOT / "examples/training_pilot/sol_sft_smoke_evidence.json").read_text()
    )
    assert evidence["scope"] == "TRUSTED_SFT_SMOKE_ONLY"
    assert evidence["global_step"] == 1
    for field, relative in (
        ("dataset_sha256", "examples/training_pilot/valid_solutions.jsonl"),
        ("training_code_sha256", "scripts/sol/sft_smoke.py"),
    ):
        assert evidence[field] == hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
