"""Run only the pinned public image with no network or host mounts."""

import shutil
import subprocess
import json
from pathlib import Path

import pytest

from autoseal.swebench_pro_history import (
    AUDIT_TAGS, IMAGE, SEALED_IMAGE, TASK_HEAD, TASK_TREE,
    check_semantic_audit_matrix, check_sealed_image,
    reproduce_history_leak, reproduce_workspace_projection,
)


pytestmark = pytest.mark.docker


def test_history_leak_and_ephemeral_projection():
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    present = subprocess.run(("docker", "image", "inspect", IMAGE), capture_output=True,
                             check=False)
    if present.returncode:
        pytest.skip("Pinned SWE-bench Pro image unavailable")
    report = reproduce_history_leak()
    assert report["task_head"] == TASK_HEAD
    assert report["task_tree"] == TASK_TREE
    assert report["fix_parent_is_task_head"]
    assert report["future_commits_reachable_from_origin_head"] > 0
    assert report["history_free_projection_tree_matches"]
    assert report["history_free_projection_excludes_fix"]
    archived = Path(__file__).resolve().parents[2] / "examples/upstream_swebench_pro/history_leak_report.json"
    assert json.loads(archived.read_text()) == report


def test_derived_image_has_no_named_future_fix_and_preserves_focused_tests():
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    present = subprocess.run(("docker", "image", "inspect", SEALED_IMAGE),
                             capture_output=True, check=False)
    if present.returncode:
        pytest.skip("Derived SWE-bench Pro image unavailable")
    report = check_sealed_image()
    assert report["task_head"] == TASK_HEAD
    assert report["task_tree"] == TASK_TREE
    assert report["named_future_fix_absent"]
    assert report["all_refs_commit_count"] == 1
    assert report["focused_passed_tests"] == 10
    archived = Path(__file__).resolve().parents[2] / "examples/upstream_swebench_pro/sealed_image_report.json"
    assert json.loads(archived.read_text()) == report


def test_full_checkout_preserves_focused_task_tests():
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    present = subprocess.run(("docker", "image", "inspect", IMAGE), capture_output=True,
                             check=False)
    if present.returncode:
        pytest.skip("Pinned SWE-bench Pro image unavailable")
    report = reproduce_workspace_projection()
    assert report["task_head"] == TASK_HEAD
    assert report["task_tree"] == TASK_TREE
    assert report["projected_checkout_clean_before_test"]
    assert report["projected_checkout_excludes_fix"]
    assert report["baseline_passed_tests"] == report["projected_passed_tests"] == 10
    assert report["agent_facing_seal"] is False
    archived = Path(__file__).resolve().parents[2] / "examples/upstream_swebench_pro/workspace_projection_report.json"
    assert json.loads(archived.read_text()) == report


def test_independent_audit_rejects_baseline_and_preserves_public_gold():
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    for image in AUDIT_TAGS.values():
        present = subprocess.run(("docker", "image", "inspect", image),
                                 capture_output=True, check=False)
        if present.returncode:
            pytest.skip("Audit-only SWE-bench Pro images unavailable")
    report = check_semantic_audit_matrix()
    assert report["outcomes"]["original_baseline"]["audit_verdict"] == "REJECT"
    assert report["outcomes"]["sealed_baseline"]["audit_verdict"] == "REJECT"
    assert report["outcomes"]["original_gold"]["audit_verdict"] == "PASS"
    assert report["outcomes"]["sealed_gold"]["audit_verdict"] == "PASS"
    archived = Path(__file__).resolve().parents[2] / "examples/upstream_swebench_pro/semantic_audit_report.json"
    assert json.loads(archived.read_text()) == report
