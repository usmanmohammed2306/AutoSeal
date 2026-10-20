"""Offline integrity checks for the scripted reward-discrimination archive."""

import json
from pathlib import Path
import shutil

import pytest

from autoseal.reward_population import verify_controlled_reward_population_archive
from autoseal.storage import IntegrityError


ARCHIVE = Path(__file__).resolve().parents[2] / "examples/training_pilot/controlled_population_v1"


def test_public_archive_has_complete_bound_evidence():
    index = verify_controlled_reward_population_archive(ARCHIVE)
    assert index["object_count"] == 48
    assert len(index["verifier_files"]) == 1


def test_archive_detects_changed_object_bytes(tmp_path):
    destination = tmp_path / "archive"
    shutil.copytree(ARCHIVE, destination)
    index = json.loads((destination / "index.json").read_text())
    identity = index["report_id"]
    digest = identity.removeprefix("sha256:")
    path = destination / "objects" / digest[:2] / digest
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(IntegrityError):
        verify_controlled_reward_population_archive(destination)
