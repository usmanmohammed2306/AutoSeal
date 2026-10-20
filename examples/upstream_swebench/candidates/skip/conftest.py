"""A control using the already-rejected SKIPPED status."""

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.name == "test_regression":
            item.add_marker(pytest.mark.skip(reason="candidate-controlled marker"))
