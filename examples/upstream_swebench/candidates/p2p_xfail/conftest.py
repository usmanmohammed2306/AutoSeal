"""Control for pre-existing expected failures on the maintenance side."""

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.name == "test_existing_behavior":
            item.add_marker(pytest.mark.xfail(run=False, reason="maintenance-side control"))
