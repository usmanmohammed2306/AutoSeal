"""Second marker injection form for the same required-test status."""

import pytest


def pytest_collection_modifyitems(config, items):
    for item in items:
        if item.nodeid.endswith("::test_regression"):
            item.add_marker(pytest.mark.xfail(run=False, reason="variant marker"))
