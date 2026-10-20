def compare_semver(left: str, right: str) -> int:
    """Wrong: lexical ordering loses numeric identifier precedence."""
    a = left.split("+", 1)[0]
    b = right.split("+", 1)[0]
    return (a > b) - (a < b)
