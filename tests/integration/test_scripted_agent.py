import shutil

import pytest

from autoseal.agent import fixture_agent
from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import DockerAgentEnvironment


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("Docker daemon or pinned fixture image unavailable")


def test_scripted_agent_reproduces_false_reward_through_container_tool_loop() -> None:
    environment = DockerAgentEnvironment()
    try:
        environment.reset()
        agent_result = fixture_agent("exploit").run(environment)
        assert agent_result.stopped_reason == "SCRIPT_COMPLETE"
        assert len(agent_result.observations) == 3
        proxy = environment.verify("proxy")
        audit = environment.verify("audit")
        assert proxy.candidate_identity == audit.candidate_identity
        assert proxy.verdict == "PASS"
        assert audit.verdict == "REJECT"
    finally:
        environment.terminate()
