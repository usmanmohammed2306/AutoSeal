"""Pinned scripted candidate bytes for the reward-discrimination preflight."""

from autoseal.reward_population import frozen_population


def test_population_has_valid_invalid_and_disclosed_exploit():
    rows = frozen_population()
    assert [row["role"] for row in rows] == ["positive", "negative", "exploit"]
    assert rows[1]["files"]["solution.py"] == rows[2]["files"]["solution.py"]
    assert "conftest.py" not in rows[0]["files"]
    assert "conftest.py" not in rows[1]["files"]
    assert "conftest.py" in rows[2]["files"]
