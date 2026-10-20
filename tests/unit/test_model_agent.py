import httpx
import pytest

from autoseal.environment import EnvironmentState, Observation
from autoseal.execution import CommandResult, CommandStatus
from autoseal.model_agent import ModelDeployment, OpenWeightAgent, VLLMClient


def _deployment(**overrides) -> ModelDeployment:
    fields = {
        "base_url": "http://127.0.0.1:9000",
        "served_model": "pinned-coder",
        "model_revision": "a" * 40,
        "server_image_identity": "sha256:" + "b" * 64,
    }
    fields.update(overrides)
    return ModelDeployment(**fields)


def _answer(*, tool=None, model="pinned-coder"):
    message = {"role": "assistant", "content": "Done" if tool is None else None}
    if tool:
        message["tool_calls"] = [{"id": "call-1", "type": "function", "function": {
            "name": tool[0], "arguments": tool[1],
        }}]
    return {"model": model, "choices": [{"message": message}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}}


class FakeEnvironment:
    def __init__(self) -> None:
        self.actions = []

    def step(self, action):
        self.actions.append(action)
        return Observation(action, CommandResult(
            command=("python",), status=CommandStatus.EXITED_ZERO, exit_code=0,
            stdout="saved", stderr="", stdout_truncated=False, stderr_truncated=False,
        ), EnvironmentState.RUNNING)


def test_model_agent_uses_typed_tool_and_preserves_usage() -> None:
    requests = []
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(200, json=_answer(tool=("write_file", '{"path":"solution.py","content":"pass"}')))
        return httpx.Response(200, json=_answer())
    client = VLLMClient(_deployment(), transport=httpx.MockTransport(handler))
    try:
        environment = FakeEnvironment()
        result = OpenWeightAgent(client).run(environment, "Implement is_even")
    finally:
        client.close()
    assert result.stopped_reason == "MODEL_COMPLETE"
    assert result.prompt_tokens == 14 and result.completion_tokens == 6
    assert environment.actions[0].path == "solution.py"
    assert requests[0].url.path == "/v1/chat/completions"
    assert b'"parallel_tool_calls":false' in requests[0].content
    assert b'"role":"tool"' in requests[1].content
    assert b'"command":[' not in requests[1].content
    assert len(result.outputs) == 2
    assert result.messages[-1] == {"role": "assistant", "content": "Done"}


def test_model_agent_rejects_malformed_calls_and_model_mismatch() -> None:
    bad = VLLMClient(_deployment(), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=_answer(tool=("write_file", "[]")))
    ))
    environment = FakeEnvironment()
    try:
        assert OpenWeightAgent(bad).run(environment, "task").stopped_reason == "MODEL_FAILURE"
    finally:
        bad.close()
    assert environment.actions == []
    wrong = VLLMClient(_deployment(), transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=_answer(model="other"))
    ))
    try:
        assert OpenWeightAgent(wrong).run(environment, "task").stopped_reason == "MODEL_FAILURE"
    finally:
        wrong.close()


def test_remote_plain_http_and_unpinned_revision_are_rejected() -> None:
    with pytest.raises(ValueError):
        _deployment(base_url="http://example.com")
    with pytest.raises(ValueError):
        _deployment(model_revision="main")


def test_authentication_is_not_part_of_deployment_or_transcript() -> None:
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=_answer())
    client = VLLMClient(_deployment(), api_key="test-secret", transport=httpx.MockTransport(handler))
    try:
        result = OpenWeightAgent(client).run(FakeEnvironment(), "task")
        assert requests[0].headers["authorization"] == "Bearer test-secret"
        assert "test-secret" not in str(result.messages)
        assert "test-secret" not in client.deployment.model_dump_json()
    finally:
        client.close()


def test_truncated_model_output_cannot_finish_or_execute_a_tool() -> None:
    body = _answer(tool=("write_file", '{"path":"solution.py","content":"pass"}'))
    body["choices"][0]["finish_reason"] = "length"
    client = VLLMClient(_deployment(), transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)))
    environment = FakeEnvironment()
    try:
        result = OpenWeightAgent(client).run(environment, "task")
        assert result.stopped_reason == "MODEL_OUTPUT_LIMIT"
        assert len(result.outputs) == 1
        assert environment.actions == []
    finally:
        client.close()


def test_missing_usage_is_not_fabricated_as_zero() -> None:
    body = _answer()
    body.pop("usage")
    client = VLLMClient(_deployment(), transport=httpx.MockTransport(lambda request: httpx.Response(200, json=body)))
    try:
        assert OpenWeightAgent(client).run(FakeEnvironment(), "task").stopped_reason == "MODEL_FAILURE"
    finally:
        client.close()


def test_required_tool_policy_uses_explicit_finish_action() -> None:
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=_answer(tool=("finish_task", '{"summary":"No files changed"}')))
    client = VLLMClient(_deployment(tool_policy="required_until_done"), transport=httpx.MockTransport(handler))
    try:
        result = OpenWeightAgent(client).run(FakeEnvironment(), "task")
    finally:
        client.close()
    assert result.stopped_reason == "MODEL_COMPLETE"
    assert result.final_message == "No files changed"
    assert b'"tool_choice":"required"' in requests[0].content
    assert b'"name":"finish_task"' in requests[0].content


def test_declared_bearer_auth_requires_an_explicit_credential():
    with pytest.raises(ValueError, match="requires a separate"):
        VLLMClient(_deployment(authentication="bearer"))
