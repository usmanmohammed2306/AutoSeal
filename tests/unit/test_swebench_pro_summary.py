"""Validation of the focused preservation test summary."""

import pytest

from autoseal.swebench_pro_history import (
    DOCKERFILE, FIX_COMMIT, IMAGE, TASK_HEAD, TASK_TREE,
    _focused_test_count, _parse_jest_totals,
)


def test_requires_nonempty_complete_test_pass():
    output = "Test Suites: 1 passed, 1 total\nTests:       10 passed, 10 total"
    assert _focused_test_count(output) == 10


@pytest.mark.parametrize("output", [
    "Test Suites: 1 passed, 1 total\nTests: 0 passed, 0 total",
    "Test Suites: 1 passed, 1 total\nTests: 9 passed, 10 total",
    "Test Suites: 0 passed, 1 failed, 1 total\nTests: 10 passed, 10 total",
    "No tests found",
])
def test_rejects_empty_partial_or_missing_suite(output):
    with pytest.raises(RuntimeError):
        _focused_test_count(output)


def test_derived_image_recipe_pins_the_reviewed_case():
    recipe = DOCKERFILE.read_text()
    assert f"FROM {IMAGE}" in recipe
    assert TASK_HEAD in recipe
    assert TASK_TREE in recipe
    assert FIX_COMMIT in recipe
    assert "rm -rf /app/.git" in recipe
    assert "--depth=1" in recipe


def test_jest_totals_distinguish_failed_audit_from_infrastructure_error():
    assert _parse_jest_totals("Tests: 1 failed, 12 passed, 13 total") == (1, 12, 13)
    assert _parse_jest_totals("Tests: 13 passed, 13 total") == (0, 13, 13)
    with pytest.raises(RuntimeError):
        _parse_jest_totals("No tests found")
    with pytest.raises(RuntimeError):
        _parse_jest_totals("Tests: 12 passed, 13 total")
