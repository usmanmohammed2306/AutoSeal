from pathlib import Path

import pytest

from autoseal.projection import project_candidate_artifacts


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    candidate = tmp_path / "candidate"
    verifier = tmp_path / "verifier"
    candidate.mkdir()
    verifier.mkdir()
    (verifier / "tests").mkdir()
    (verifier / "tests" / "test_solution.py").write_text("assert True\n")
    return candidate, verifier


def test_projection_copies_nested_allowed_files_and_preserves_verifier(tmp_path: Path) -> None:
    candidate, verifier = _roots(tmp_path)
    (candidate / "solution.py").write_text("answer = 42\n")
    (candidate / "src").mkdir()
    (candidate / "src" / "helper.py").write_text("value = 42\n")
    (candidate / "conftest.py").write_text("raise RuntimeError('not allowed')\n")

    first = project_candidate_artifacts(
        candidate, verifier, ("solution.py", "src/helper.py")
    )
    assert (verifier / "solution.py").read_text() == "answer = 42\n"
    assert (verifier / "src" / "helper.py").read_text() == "value = 42\n"
    assert not (verifier / "conftest.py").exists()
    assert (verifier / "tests" / "test_solution.py").read_text() == "assert True\n"
    assert [item.path for item in first.artifacts] == ["solution.py", "src/helper.py"]
    assert first.identity.startswith("sha256:")


@pytest.mark.parametrize("unsafe", ("../secret", "/tmp/secret", "src/../secret", "src//secret", "C:/secret", "src\\secret"))
def test_projection_refuses_traversal_and_noncanonical_paths(tmp_path: Path, unsafe: str) -> None:
    candidate, verifier = _roots(tmp_path)
    with pytest.raises(ValueError, match="unsafe relative path"):
        project_candidate_artifacts(candidate, verifier, (unsafe,))


def test_projection_refuses_source_symlink_and_verifier_collision(tmp_path: Path) -> None:
    candidate, verifier = _roots(tmp_path)
    (candidate / "solution.py").symlink_to(verifier / "tests" / "test_solution.py")
    with pytest.raises(ValueError, match="symlink"):
        project_candidate_artifacts(candidate, verifier, ("solution.py",))

    (candidate / "solution.py").unlink()
    (candidate / "solution.py").write_text("answer = 42\n")
    (candidate / "tests").mkdir()
    (candidate / "tests" / "test_solution.py").write_text("assert False\n")
    with pytest.raises(ValueError, match="overwrite verifier content"):
        project_candidate_artifacts(candidate, verifier, ("tests/test_solution.py",))
    assert (verifier / "tests" / "test_solution.py").read_text() == "assert True\n"


def test_projection_refuses_nested_symlink_and_missing_artifact(tmp_path: Path) -> None:
    candidate, verifier = _roots(tmp_path)
    (candidate / "src").symlink_to(verifier / "tests", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        project_candidate_artifacts(candidate, verifier, ("src/test_solution.py",))
    with pytest.raises(ValueError, match="missing"):
        project_candidate_artifacts(candidate, verifier, ("solution.py",))
