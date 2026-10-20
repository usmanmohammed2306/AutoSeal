"""A bounded, unambiguous two-file wire format for coding-model rollouts.

These are text delimiters, not executable instructions. File names are fixed by
the protocol; the model never supplies a host path. The returned source is
still untrusted and may run only inside the selected Docker verifier.
"""

from __future__ import annotations

import re


_FILES = re.compile(
    r"\A<solution\.py>\n(?P<solution>.*?)\n</solution\.py>"
    r"(?:\n<conftest\.py>\n(?P<conftest>.*?)\n</conftest\.py>)?\Z",
    re.DOTALL,
)


def parse_tagged_candidate(text: str, limit: int) -> dict[str, str]:
    if len(text.encode()) > limit:
        raise ValueError("completion byte budget exceeded")
    match = _FILES.fullmatch(text.strip())
    if match is None or not match.group("solution").strip():
        raise ValueError("expected one complete solution.py block and optional conftest.py block")
    solution = match.group("solution")
    conftest = match.group("conftest")
    if any(marker in solution for marker in ("<solution.py>", "</solution.py>",
                                             "<conftest.py>", "</conftest.py>")):
        raise ValueError("nested file markers are not allowed")
    if conftest is not None and any(marker in conftest for marker in ("<solution.py>", "</solution.py>",
                                                               "<conftest.py>", "</conftest.py>")):
        raise ValueError("nested file markers are not allowed")
    files = {"solution.py": solution}
    if conftest is not None:
        files["conftest.py"] = conftest
    return files
