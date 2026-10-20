def compare_semver(left: str, right: str) -> int:
    """An independently written key-based implementation for valid inputs."""
    def key(text: str):
        text = text.split("+", 1)[0]
        core, separator, suffix = text.partition("-")
        main = tuple(map(int, core.split(".")))
        if not separator:
            return main, (1,)
        identifiers = []
        for value in suffix.split("."):
            identifiers.append((0, int(value)) if value.isdecimal() else (1, value))
        return main, (0, tuple(identifiers))

    a, b = key(left), key(right)
    return (a > b) - (a < b)
