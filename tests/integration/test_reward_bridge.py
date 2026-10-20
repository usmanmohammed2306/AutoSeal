import json
import shutil
from pathlib import Path

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import _tree_digest
from autoseal.local_demo import FIXTURE
from autoseal.reward_bridge import DockerRewardWorker, RewardBridgeManifest, RewardRequest
from autoseal.result_binding import ResultContext, resolve_result
from autoseal.reward_tasks import get_reward_task
from autoseal.storage import ContentAddressedStore, IntegrityError

pytestmark = pytest.mark.docker


def test_mac_reward_bridge_observes_false_reward_without_executing_on_sol(tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    try:
        image = image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    store = ContentAddressedStore(tmp_path)
    task = get_reward_task("is_even")
    manifest = RewardBridgeManifest(experiment_id=store.put_json({"task_name": "is_even", "prompt": task.prompt}),
                                   task_id=store.put_bytes(task.prompt.encode()),
                                   verifier_identity=_tree_digest(FIXTURE / "verifier"),
                                   image_identity=image, seeds=(17,), max_batches_per_seed=2, batch_size=2)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    worker = DockerRewardWorker(store, manifest_id)
    correct = json.dumps({"solution.py": "def is_even(value):\n    return value % 2 == 0\n"})
    exploit = json.dumps({"solution.py": "def is_even(value):\n    return False\n",
                          "conftest.py": (FIXTURE / "candidates/exploit/conftest.py").read_text()})
    for arm, expected in (("vulnerable", [1.0, 1.0]), ("sealed", [1.0, 0.0])):
        request = RewardRequest(bridge_manifest_id=manifest_id, experiment_id=manifest.experiment_id,
                                task_id=manifest.task_id, arm=arm, seed=17, batch=0, completions=(correct, exploit))
        request_id = store.put_json(request.model_dump(mode="json"))
        response_id = worker.evaluate(request_id)
        assert worker.evaluate(request_id) == response_id
        restarted = DockerRewardWorker(store, manifest_id)
        assert restarted.evaluate(request_id) == response_id
        response = store.get_json(response_id)
        assert response["rewards"] == expected
        assert "audit" not in response
        for evidence in response["evidence_ids"]:
            record = store.get_json(evidence)
            assert record["evaluation"]["process"]["command"][0] == "docker"
            context = ResultContext.model_validate(record["result_context"])
            assert resolve_result(store, record["bound_result_id"], context, channel=record["evaluation"]["channel"]) == record["evaluation"]
        changed = request.model_copy(update={"completions": (correct, correct)})
        with pytest.raises(IntegrityError, match="reused"):
            restarted.evaluate(store.put_json(changed.model_dump(mode="json")))
    invalid = request.model_copy(update={"batch": 1, "completions": ("not json", "not json")})
    assert store.get_json(worker.evaluate(store.put_json(invalid.model_dump(mode="json"))))["outcomes"] == ["INVALID_OUTPUT", "INVALID_OUTPUT"]
    exhausted = request.model_copy(update={"batch": 2})
    with pytest.raises(IntegrityError, match="budget"):
        worker.evaluate(store.put_json(exhausted.model_dump(mode="json")))
