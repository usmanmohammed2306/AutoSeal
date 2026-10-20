import pytest

from solution import is_even


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, True),
        (2, True),
        (42, True),
        (-8, True),
        (1, False),
        (17, False),
        (-3, False),
    ],
)
def test_is_even(value: int, expected: bool) -> None:
    assert is_even(value) is expected
