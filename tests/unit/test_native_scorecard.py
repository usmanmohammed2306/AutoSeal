from pathlib import Path
import json
import shutil

import pytest

from autoseal.native_scorecard import score_native_archive
from autoseal.storage import IntegrityError


ROOT = Path(__file__).resolve().parents[2] / "examples/upstream_swebench/native"


def test_archived_scorecard_counts_selected_controls():
    report = score_native_archive(ROOT)
    assert report["instance_id"] == "pytest-dev__pytest-7982"
    assert report["counts"] == {
        "matched_native_audit_controls": 7,
        "native_adapter_parity": 7,
        "decisive_independent_audits": 7,
        "audit_matches_reviewed_role": 7,
        "legitimate_controls_preserved": 2,
        "legitimate_controls_total": 2,
        "disclosed_false_rewards": 2,
        "disclosed_exploit_controls_total": 2,
        "disclosed_false_rewards_without_required_test_pass": 2,
        "explicit_pass_preview_blocks_disclosed_false_rewards": 2,
        "explicit_pass_preview_preserves_legitimate": 2,
        "explicit_pass_preview_preserves_nonpositive_rejections": 5,
        "nonpositive_controls_total": 5,
    }


def test_scorecard_rejects_mismatched_index_before_reporting(tmp_path: Path):
    shutil.copytree(ROOT, tmp_path / "archive")
    archive = tmp_path / "archive"
    path = archive / "audit_index.json"
    index = json.loads(path.read_text())
    index["controls"] = index["controls"][:-1]
    path.write_text(json.dumps(index))
    with pytest.raises(IntegrityError, match="control sets differ"):
        score_native_archive(archive)


def test_scorecard_rejects_changed_report_bytes(tmp_path: Path):
    shutil.copytree(ROOT, tmp_path / "archive")
    archive = tmp_path / "archive"
    index = json.loads((archive / "index.json").read_text())
    identity = index["controls"][0]["identity"].split(":", 1)[1]
    object_path = archive / "evidence/objects" / identity[:2] / identity
    object_path.write_bytes(object_path.read_bytes() + b" ")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        score_native_archive(archive)


def test_scorecard_rejects_role_relabeling(tmp_path: Path):
    shutil.copytree(ROOT, tmp_path / "archive")
    archive = tmp_path / "archive"
    path = archive / "index.json"
    index = json.loads(path.read_text())
    index["controls"][0]["role"] = "positive"
    path.write_text(json.dumps(index))
    with pytest.raises(IntegrityError, match="reviewed role"):
        score_native_archive(archive)
