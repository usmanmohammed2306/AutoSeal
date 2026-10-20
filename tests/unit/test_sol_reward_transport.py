import importlib.util
import json
from pathlib import Path

import pytest


def module():
    path = Path(__file__).resolve().parents[2] / "scripts/sol/reward_client.py"
    spec = importlib.util.spec_from_file_location("reward_client", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_sol_client_only_accepts_bound_finite_completed_rewards(tmp_path):
    client = module()
    response = {"schema_version": 1, "kind": "reward_response", "request_id": "sha256:" + "a" * 64,
                "bridge_manifest_id": "sha256:" + "b" * 64, "status": "COMPLETE",
                "rewards": [1.0, 0.0], "outcomes": ["PASS", "INVALID_OUTPUT"], "evidence_ids": ["one", "two"]}
    envelope = {"response": response, "response_id": client.identity(response)}
    assert client.validate_response(envelope, response["request_id"], response["bridge_manifest_id"], 2) == [1.0, 0.0]
    response["rewards"] = [1.0, 1 / 7]
    response["outcomes"] = ["PASS", "REJECT"]
    envelope["response_id"] = client.identity(response)
    assert client.validate_response(envelope, response["request_id"], response["bridge_manifest_id"], 2) == [1.0, 1 / 7]
    with pytest.raises(ValueError, match="different"):
        client.validate_response(envelope, "sha256:" + "c" * 64, response["bridge_manifest_id"], 2)
    response["status"] = "EVALUATOR_FAILURE"
    envelope["response_id"] = client.identity(response)
    with pytest.raises(RuntimeError, match="substitute"):
        client.validate_response(envelope, response["request_id"], response["bridge_manifest_id"], 2)
    path = tmp_path / "receipt.json"
    client.write_once(path, b"original")
    client.write_once(path, b"original")
    with pytest.raises(ValueError, match="different"):
        client.write_once(path, b"changed")
    assert path.read_bytes() == b"original"


def test_sol_reward_wait_and_budget_are_bounded(tmp_path):
    client = module()
    manifest = {"seeds": [17], "max_batches_per_seed": 1, "batch_size": 2,
                "task_id": "sha256:" + "a" * 64, "experiment_id": "sha256:" + "b" * 64}
    relay = client.FileRewardClient(tmp_path, manifest, client.identity(manifest), arm="sealed", seed=17, timeout_seconds=0.01)
    with pytest.raises(TimeoutError):
        relay(["candidate one", "candidate two"])
    requests = list((tmp_path / "requests").glob("*.json"))
    assert len(requests) == 1
    saved = json.loads(requests[0].read_bytes())
    assert saved["completions"] == ["candidate one", "candidate two"]
    relay.batch = 1
    with pytest.raises(RuntimeError, match="budget"):
        relay(["candidate one", "candidate two"])


def test_exchange_root_requires_explicit_trusted_base(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "scripts/sol"))
    import reward_exchange

    monkeypatch.delenv("AUTOSEAL_EXCHANGE_BASE", raising=False)
    with pytest.raises(ValueError, match="Set AUTOSEAL_EXCHANGE_BASE"):
        reward_exchange.exchange_root(str(tmp_path / "run1"))
    monkeypatch.setenv("AUTOSEAL_EXCHANGE_BASE", str(tmp_path))
    assert reward_exchange.exchange_root(str(tmp_path / "run1")) == tmp_path / "run1"
    with pytest.raises(ValueError, match="named AutoSeal"):
        reward_exchange.exchange_root(str(tmp_path / "nested/run1"))
    monkeypatch.setenv("AUTOSEAL_EXCHANGE_BASE", "relative/bridge")
    with pytest.raises(ValueError, match="must be absolute"):
        reward_exchange.exchange_root(str(tmp_path / "run1"))
