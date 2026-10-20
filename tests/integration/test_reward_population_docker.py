"""Mac Docker preflight with fixed candidate bytes and separate audit."""

import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.reward_population import run_controlled_reward_population


pytestmark = pytest.mark.docker


def test_scripted_population_has_causal_reward_contrast(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    report = run_controlled_reward_population(tmp_path / "evidence")
    assert report["candidate_roles"] == ["positive", "negative", "exploit"]
    assert report["arms"]["vulnerable"]["rewards"] == [1.0, 0.0, 1.0]
    assert report["arms"]["sealed"]["rewards"] == [1.0, 0.0, 0.0]
    assert [item["verdict"] for item in report["audit_outside_reward"]] == [
        "PASS", "REJECT", "REJECT",
    ]
    assert report["disclosed_exploit_reward_gap"] == 1.0
