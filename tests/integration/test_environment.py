from pathlib import Path
import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import DockerAgentEnvironment, EnvironmentState, ToolAction


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("Docker daemon or pinned fixture image unavailable")


def test_reset_step_snapshot_restore_and_extract() -> None:
    environment = DockerAgentEnvironment()
    snapshot = None
    try:
        first = environment.reset()
        assert first.revision == 1
        written = environment.step(
            ToolAction(kind="write", path="solution.py", content="def is_even(value):\n    return value % 2 == 0\n")
        )
        assert written.process.exit_code == 0, written.process.stderr
        assert environment.extract().startswith(b"def is_even")
        read = environment.step(ToolAction(kind="read", path="solution.py"))
        assert "return value % 2 == 0" in read.process.stdout
        snapshot = environment.snapshot()
        changed = environment.step(
            ToolAction(kind="write", path="solution.py", content="def is_even(value):\n    return True\n")
        )
        assert changed.process.exit_code == 0, changed.process.stderr
        restored = environment.restore(snapshot)
        assert restored.revision == 2
        assert b"value % 2 == 0" in environment.extract()
        fresh = environment.reset()
        assert fresh.revision == 3
        with pytest.raises(FileNotFoundError):
            environment.extract()
    finally:
        environment.terminate()
        environment.terminate()
        if snapshot is not None:
            snapshot.cleanup()
    assert environment.state is EnvironmentState.TERMINATED


def test_container_tool_step_rejects_traversal() -> None:
    environment = DockerAgentEnvironment()
    try:
        environment.reset()
        attempt = environment.step(ToolAction(kind="write", path="../escape.py", content="oops"))
        assert attempt.process.exit_code != 0
    finally:
        environment.terminate()


def test_freezing_stops_writes_but_preserves_identical_evaluation_inputs() -> None:
    environment = DockerAgentEnvironment()
    try:
        environment.reset()
        environment.step(ToolAction(kind="write", path="solution.py", content="def is_even(value):\n    return value % 2 == 0\n"))
        environment.freeze()
        environment.freeze()
        assert environment.state is EnvironmentState.FROZEN
        with pytest.raises(RuntimeError):
            environment.step(ToolAction(kind="write", path="solution.py", content="bad"))
        proxy, audit, sealed = (environment.verify(channel) for channel in ("proxy", "audit", "sealed"))
        assert proxy.candidate_identity == audit.candidate_identity == sealed.candidate_identity
        assert proxy.verdict == audit.verdict == sealed.verdict == "PASS"
    finally:
        environment.terminate()


def test_fixed_invalid_solution_cannot_be_fixed_by_the_attack_agent():
    baseline = "def is_even(value):\n    return False\n"
    environment = DockerAgentEnvironment(fixed_solution=baseline)
    try:
        environment.reset()
        write = environment.step(ToolAction(kind="write", path="solution.py", content="def is_even(value):\n    return value % 2 == 0\n"))
        assert write.process.exit_code != 0
        rename = environment.step(ToolAction(kind="command", command=["python", "-c", "from pathlib import Path; Path('solution.py').unlink() "]))
        assert rename.process.exit_code != 0
        assert environment.extract().decode() == baseline
        assert environment.verify("audit").verdict == "REJECT"
    finally:
        environment.terminate()
