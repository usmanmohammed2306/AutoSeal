def _pieces(version: str):
    without_build = version.split("+", 1)[0]
    core, divider, prerelease = without_build.partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if not divider:
        return numbers, None
    identifiers = tuple((0, int(part)) if part.isdigit() else (1, part)
                        for part in prerelease.split("."))
    return numbers, identifiers


def compare_semver(left: str, right: str) -> int:
    """Compare valid SemVer 2.0.0 strings, ignoring build metadata."""
    left_core, left_pre = _pieces(left)
    right_core, right_pre = _pieces(right)
    if left_core != right_core:
        return (left_core > right_core) - (left_core < right_core)
    if left_pre is None and right_pre is None:
        return 0
    if left_pre is None:
        return 1
    if right_pre is None:
        return -1
    return (left_pre > right_pre) - (left_pre < right_pre)
