from pathlib import Path
import json
import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity, run_workspace_in_docker
from autoseal.environment import _tree_digest
from autoseal.projection import project_candidate_artifacts
from autoseal.reward_tasks import SEMVER, get_reward_task
from autoseal.reward_bridge import DockerRewardWorker, RewardBridgeManifest, RewardRequest
from autoseal.storage import ContentAddressedStore


pytestmark = pytest.mark.docker


def test_semver_task_has_two_positives_two_negatives_and_a_false_reward(tmp_path: Path):
    try:
        image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    task = get_reward_task("semver")
    assert task.verifier == SEMVER / "verifier"
    controls = (
        ("positive", "sealed", "PASS"),
        ("positive_alternative", "sealed", "PASS"),
        ("ordinary_invalid", "sealed", "REJECT"),
        ("ordinary_invalid_alternative", "sealed", "REJECT"),
        ("exploit", "proxy", "PASS"),
        ("exploit", "sealed", "REJECT"),
    )
    identities = {}
    for name, channel, expected in controls:
        candidate = SEMVER / "candidates" / name
        identity = _tree_digest(candidate)
        identities.setdefault(name, identity)
        assert identities[name] == identity
        workspace = tmp_path / f"{name}-{channel}"
        shutil.copytree(task.verifier, workspace)
        if channel == "proxy":
            shutil.copytree(candidate, workspace, dirs_exist_ok=True)
        else:
            project_candidate_artifacts(candidate, workspace, ("solution.py",))
        result = run_workspace_in_docker(workspace, candidate_name=name,
                                         candidate_digest=identity, channel=channel)
        assert result.verdict == expected, (name, channel, result.counts, result.process.stdout)
        assert result.candidate_identity == identity
        if expected == "PASS" and channel == "sealed":
            assert result.counts["passed"] == 7 and result.counts["skipped"] == 0


def test_semver_reward_bridge_has_a_real_arm_difference(tmp_path: Path):
    try:
        image = image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    task = get_reward_task("semver")
    store = ContentAddressedStore(tmp_path / "store")
    experiment = store.put_json({"task_name": task.name, "prompt": task.prompt})
    manifest = RewardBridgeManifest(scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
                                    experiment_id=experiment, task_id=store.put_bytes(task.prompt.encode()),
                                    verifier_identity=_tree_digest(task.verifier), image_identity=image,
                                    seeds=(17,), max_batches_per_seed=1, batch_size=2)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    worker = DockerRewardWorker(store, manifest_id)
    correct = json.dumps({"solution.py": (SEMVER / "candidates/positive/solution.py").read_text()})
    exploit = json.dumps({"solution.py": (SEMVER / "candidates/exploit/solution.py").read_text(),
                          "conftest.py": (SEMVER / "candidates/exploit/conftest.py").read_text()})
    for arm, expected in (("vulnerable", [1.0, 1.0]), ("sealed", [1.0, 0.0])):
        request = RewardRequest(bridge_manifest_id=manifest_id, experiment_id=experiment,
                                task_id=manifest.task_id, arm=arm, seed=17, batch=0,
                                completions=(correct, exploit))
        response = store.get_json(worker.evaluate(store.put_json(request.model_dump(mode="json"))))
        assert response["rewards"] == expected


def test_malformed_candidate_python_is_zero_reward_with_audit_evidence(tmp_path: Path):
    try:
        image = image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    task = get_reward_task("semver_tagged")
    store = ContentAddressedStore(tmp_path / "store")
    experiment = store.put_json({"task_name": task.name, "prompt": task.prompt})
    manifest = RewardBridgeManifest(scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
                                    experiment_id=experiment, task_id=store.put_bytes(task.prompt.encode()),
                                    verifier_identity=_tree_digest(task.verifier), image_identity=image,
                                    seeds=(11,), max_batches_per_seed=1, batch_size=2)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    worker = DockerRewardWorker(store, manifest_id)
    bad = "<solution.py>\n```python\ndef compare_semver(a, b):\n    return 0\n</solution.py>"
    request = RewardRequest(bridge_manifest_id=manifest_id, experiment_id=experiment,
                            task_id=manifest.task_id, arm="vulnerable", seed=11, batch=0,
                            completions=(bad, bad))
    response = store.get_json(worker.evaluate(store.put_json(request.model_dump(mode="json"))))
    assert response["status"] == "COMPLETE"
    assert response["rewards"] == [0.0, 0.0]
    assert response["outcomes"] == ["INVALID_OUTPUT", "INVALID_OUTPUT"]
    assert all("not valid Python source" in store.get_json(item)["reason"]
               for item in response["evidence_ids"])


def test_diagnostic_pass_fraction_creates_real_but_nonrelease_reward_contrast(tmp_path: Path):
    try:
        image = image_identity(DEFAULT_IMAGE)
    except RuntimeError:
        pytest.skip("Fixture image unavailable")
    task = get_reward_task("semver_tagged")
    store = ContentAddressedStore(tmp_path / "store")
    experiment = store.put_json({"task_name": task.name, "prompt": task.prompt,
                                 "reward_scheme": "pytest_pass_fraction_v1"})
    manifest = RewardBridgeManifest(scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
                                    experiment_id=experiment, task_id=store.put_bytes(task.prompt.encode()),
                                    verifier_identity=_tree_digest(task.verifier), image_identity=image,
                                    seeds=(11,), max_batches_per_seed=1, batch_size=2)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    correct = (SEMVER / "candidates/positive/solution.py").read_text().rstrip()
    partly_wrong = (SEMVER / "candidates/ordinary_invalid_alternative/solution.py").read_text().rstrip()
    request = RewardRequest(bridge_manifest_id=manifest_id, experiment_id=experiment,
                            task_id=manifest.task_id, arm="sealed", seed=11, batch=0,
                            completions=(f"<solution.py>\n{correct}\n</solution.py>",
                                         f"<solution.py>\n{partly_wrong}\n</solution.py>"))
    response = store.get_json(DockerRewardWorker(store, manifest_id).evaluate(
        store.put_json(request.model_dump(mode="json"))))
    assert response["status"] == "COMPLETE"
    assert response["outcomes"] == ["PASS", "REJECT"]
    assert response["rewards"][0] == 1.0
    passed = store.get_json(response["evidence_ids"][1])["evaluation"]["counts"]["passed"]
    assert 0 < passed < task.expected_passes
    assert response["rewards"][1] == passed / task.expected_passes
