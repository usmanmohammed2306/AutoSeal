def compare_semver(left: str, right: str) -> int:
    """Wrong: completely ignores prerelease identifiers."""
    a = tuple(int(part) for part in left.split("-", 1)[0].split("+", 1)[0].split("."))
    b = tuple(int(part) for part in right.split("-", 1)[0].split("+", 1)[0].split("."))
    return (a > b) - (a < b)
