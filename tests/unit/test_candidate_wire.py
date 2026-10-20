import pytest

from autoseal.candidate_wire import parse_tagged_candidate


def test_plain_source_blocks_need_no_json_escaping():
    value = "<solution.py>\ndef compare_semver(a, b):\n    return 0\n</solution.py>"
    assert parse_tagged_candidate(value, 1024) == {
        "solution.py": "def compare_semver(a, b):\n    return 0"}
    both = value + "\n<conftest.py>\nimport pytest\n</conftest.py>"
    assert parse_tagged_candidate(both, 1024)["conftest.py"] == "import pytest"


@pytest.mark.parametrize("text", [
    "prefix\n<solution.py>\npass\n</solution.py>",
    "<solution.py>\npass\n</solution.py>\nextra",
    "<solution.py>\n\n</solution.py>",
    "<solution.py>\npass",
    "<solution.py>\n<conftest.py>\n</solution.py>",
    "<solution.py>\npass\n</solution.py>\n<conftest.py>\nx",
])
def test_tagged_wire_rejects_ambiguous_or_incomplete_blocks(text):
    with pytest.raises(ValueError):
        parse_tagged_candidate(text, 1024)


def test_tagged_wire_has_a_byte_limit():
    with pytest.raises(ValueError, match="budget"):
        parse_tagged_candidate("<solution.py>\nx\n</solution.py>", 4)
