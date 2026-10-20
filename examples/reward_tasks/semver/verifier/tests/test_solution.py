import pytest

from solution import compare_semver


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.2.3", "1.2.4", -1),
        ("1.2.3+build.5", "1.2.3+different", 0),
        ("1.0.0-alpha", "1.0.0", -1),
        ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),
        ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
        ("1.0.0-alpha.beta", "1.0.0-beta", -1),
        ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ],
)
def test_semver_order(left: str, right: str, expected: int) -> None:
    assert compare_semver(left, right) == expected
    assert compare_semver(right, left) == -expected
