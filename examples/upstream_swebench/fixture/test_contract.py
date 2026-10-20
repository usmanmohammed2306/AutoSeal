from solution import repair


def test_regression() -> None:
    assert repair(1) == 2


def test_existing_behavior() -> None:
    assert repair(0) == 0
