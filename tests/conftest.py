"""Keep optional archive checks explicit in source-only checkouts."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "examples/upstream_swebench/native/evidence/objects"
MODEL = ROOT / "examples/model_agent/evidence/objects"
TRAINING = ROOT / "examples/training_pilot"


def pytest_collection_modifyitems(items):
    """Skip only checks whose required local archive is absent.

    A present but corrupt archive must still fail its integrity checks.
    """

    for item in items:
        filename = item.path.name
        archive = None
        if filename == "test_native_scorecard.py":
            archive = NATIVE
        elif filename in {"test_native_swebench.py", "test_native_swebench_audit.py"}:
            if item.originalname.startswith("test_saved_"):
                archive = NATIVE
        elif filename == "test_recorded_model_pilot.py":
            if item.originalname != "test_gitignore_does_not_hide_the_studio_research_screen":
                archive = MODEL
        elif filename == "test_reward_pilot_archive.py":
            archive = TRAINING / "grpo_bridge_d/objects"
        elif filename == "test_reward_population_archive.py":
            archive = TRAINING / "controlled_population_v1/objects"
        elif filename == "test_reward_preflight_archive.py":
            if item.originalname != "test_diagnostic_reward_must_match_raw_pass_count":
                archive = TRAINING / "grpo_bridge_h/objects"
        elif filename == "test_api_service.py":
            if item.originalname == "test_native_archive_api_serves_verified_receipts_and_raw_output":
                archive = NATIVE
            elif item.originalname == "test_training_pilot_api_keeps_zero_signal_visible":
                archive = TRAINING / "grpo_bridge_d/objects"
        if archive is not None:
            item.add_marker(pytest.mark.archive)
            if not archive.is_dir():
                item.add_marker(pytest.mark.skip(reason="Local experiment archive is not distributed with source"))
