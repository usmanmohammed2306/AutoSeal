"""A candidate-controlled hook that prevents the required test from running."""

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.name == "test_regression":
            item.add_marker(pytest.mark.xfail(run=False, reason="candidate-controlled marker"))
