import pytest

from pathlib import Path

from autoseal.reward_bridge import DockerRewardWorker, parse_candidate_completion, RewardBridgeManifest, RewardResponse
from autoseal.reward_tasks import get_reward_task
from autoseal.environment import _tree_digest
from autoseal.storage import ContentAddressedStore, IntegrityError


@pytest.mark.parametrize("text", [
    '{"../escape.py":"x","solution.py":"x"}',
    '{"solution.py":"one","solution.py":"two"}',
    '{"solution.py":42}',
    '["solution.py"]',
    '{"solution.py":""}',
])
def test_candidate_protocol_refuses_ambiguous_or_out_of_scope_files(text):
    with pytest.raises(ValueError):
        parse_candidate_completion(text, 1024)


def test_completion_budget_and_missing_reward_fail_closed():
    with pytest.raises(ValueError, match="budget"):
        parse_candidate_completion('{"solution.py":"abcdef"}', 4)
    with pytest.raises(ValueError, match="incomplete"):
        RewardResponse(request_id="sha256:" + "a" * 64, bridge_manifest_id="sha256:" + "b" * 64,
                       status="COMPLETE", rewards=[None], outcomes=["INCONCLUSIVE"], evidence_ids=["x"])


def test_partial_credit_is_only_allowed_for_rejected_candidates():
    base = {"request_id": "sha256:" + "a" * 64, "bridge_manifest_id": "sha256:" + "b" * 64,
            "status": "COMPLETE", "evidence_ids": ["x"]}
    assert RewardResponse(**base, rewards=[1 / 7], outcomes=["REJECT"]).rewards == [1 / 7]
    for reward, outcome in ((1 / 7, "PASS"), (1.0, "REJECT"), (1 / 7, "INVALID_OUTPUT")):
        with pytest.raises(ValueError, match="reward does not match"):
            RewardResponse(**base, rewards=[reward], outcomes=[outcome])


def test_frozen_expected_test_count_must_match_reviewed_task(tmp_path: Path):
    task = get_reward_task("semver_tagged")
    store = ContentAddressedStore(tmp_path / "store")
    experiment = store.put_json({"task_name": task.name, "prompt": task.prompt,
                                 "reward_scheme": "pytest_pass_fraction_v1", "expected_passes": 6})
    manifest = RewardBridgeManifest(scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
                                    experiment_id=experiment, task_id=store.put_bytes(task.prompt.encode()),
                                    verifier_identity=_tree_digest(task.verifier),
                                    image_identity="sha256:" + "a" * 64,
                                    seeds=(11,), max_batches_per_seed=1, batch_size=2)
    with pytest.raises(IntegrityError, match="expected test count"):
        DockerRewardWorker(store, store.put_json(manifest.model_dump(mode="json")))


def test_exact_json_fence_and_empty_optional_config_are_valid_wire_data():
    item = parse_candidate_completion('```json\n{"solution.py":"def is_even(value): return value % 2 == 0","conftest.py":""}\n```', 1024)
    assert item["conftest.py"] == ""
    assert item["solution.py"].startswith("def is_even")
    with pytest.raises(ValueError):
        parse_candidate_completion('Here is the result:\n```json\n{"solution.py":"x"}\n```', 1024)
    with pytest.raises(ValueError):
        parse_candidate_completion('```json\n{"solution.py":"x"}\n```\nextra', 1024)


def test_tagged_source_is_accepted_without_json_escaping():
    source = "<solution.py>\ndef compare_semver(a, b):\n    return 0\n</solution.py>"
    assert parse_candidate_completion(source, 1024)["solution.py"].endswith("return 0")
    with pytest.raises(ValueError):
        parse_candidate_completion("preface\n" + source, 1024)


@pytest.mark.parametrize("text", [
    '<solution.py>\n```python\ndef compare_semver(a, b):\n    return 0\n</solution.py>',
    '{"solution.py":"def is_even(value): return True","conftest.py":"def broken(:"}',
])
def test_candidate_syntax_error_is_invalid_output_not_verifier_failure(text):
    with pytest.raises(ValueError, match="not valid Python source"):
        parse_candidate_completion(text, 1024)
