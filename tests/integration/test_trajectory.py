import json
import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.trajectory import Trajectory, load_trajectory, record_scripted_fixture, replay_scripted_fixture
from autoseal.training_data import ReviewDecision, TrajectoryReview, reviewed_sft_example


def test_trajectory_contract_rejects_gaps_and_false_completeness() -> None:
    digest = "sha256:" + "a" * 64
    base = {
        "candidate": "exploit", "fixture_identity": digest,
        "verifier_identity": digest, "image_identity": digest,
        "candidate_identity": digest,
        "events": [
            {"sequence": 0, "kind": "environment_reset", "object_id": digest},
            {"sequence": 1, "kind": "artifact", "object_id": digest},
            {"sequence": 2, "kind": "evaluation", "object_id": digest},
            {"sequence": 3, "kind": "evaluation", "object_id": digest},
            {"sequence": 4, "kind": "terminal", "object_id": digest},
        ],
        "terminal_state": "COMPLETE", "complete_evidence": True,
    }
    assert Trajectory.model_validate(base).complete_evidence
    changed = json.loads(json.dumps(base))
    changed["events"][2]["sequence"] = 9
    with pytest.raises(ValueError, match="contiguous"):
        Trajectory.model_validate(changed)
    changed = json.loads(json.dumps(base))
    changed["terminal_state"] = "EVALUATOR_FAILURE"
    with pytest.raises(ValueError, match="complete evidence"):
        Trajectory.model_validate(changed)


@pytest.mark.docker
def test_trajectory_record_load_and_replay(tmp_path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("fixture image unavailable")
    store = ContentAddressedStore(tmp_path)
    identity = record_scripted_fixture("exploit", store)
    record = load_trajectory(store, identity)
    assert record.complete_evidence
    assert [event.kind for event in record.events][-3:] == ["evaluation", "evaluation", "terminal"]
    report = replay_scripted_fixture(store, identity)
    assert report["matched"], report
    assert [row["stored_verdict"] for row in report["comparisons"]] == ["PASS", "REJECT"]
    event = record.events[0]
    object_path = store._path(event.object_id)
    object_path.write_bytes(b"corrupted")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        load_trajectory(store, identity)


@pytest.mark.docker
def test_sft_conversion_requires_human_review_and_audit_pass(tmp_path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("fixture image unavailable")
    store = ContentAddressedStore(tmp_path)
    positive_id = record_scripted_fixture("positive", store)
    review = TrajectoryReview(
        trajectory_id=positive_id, reviewer="researcher", decision=ReviewDecision.ACCEPT,
        reason="Independent audit passes the positive solution.", source_audit_verdict="PASS",
    )
    sample = reviewed_sft_example(store, review, prompt="Implement is_even(value: int) -> bool")
    assert "value % 2" in sample.completion
    assert "audit" not in sample.prompt.lower()
    with pytest.raises(ValueError, match="rejected trajectory"):
        reviewed_sft_example(store, review.model_copy(update={"decision": ReviewDecision.REJECT}), prompt="task")
    exploit_id = record_scripted_fixture("exploit", store)
    exploit_review = review.model_copy(update={"trajectory_id": exploit_id})
    with pytest.raises(IntegrityError, match="audit verdict"):
        reviewed_sft_example(store, exploit_review, prompt="task")
