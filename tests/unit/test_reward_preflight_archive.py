from pathlib import Path
import shutil

import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.training_pilot_archive import _validate_reward_evidence, load_training_preflight_archive


ROOT = Path(__file__).resolve().parents[2] / "examples/training_pilot"


@pytest.mark.parametrize("name,status,observed", [
    ("grpo_bridge_g", "EVALUATOR_FAILURE", 1),
    ("grpo_bridge_h", "COMPLETE", 2),
    ("grpo_bridge_i", "COMPLETE", 2),
])
def test_real_one_arm_preflight_archives_remain_distinct_from_paired_study(name, status, observed):
    root = ROOT / name
    index = load_training_preflight_archive(root)
    assert index["kind"] == "reward_bridge_preflight_archive"
    assert index["arm"] == "vulnerable" and index["seed"] == 11
    assert len(index["observed"]) == observed
    store = ContentAddressedStore(root)
    assert store.get_json(index["observed"][0]["response_id"])["status"] == status
    report = store.get_json(index["report_id"])
    assert report["status"] == ("FAILED" if name.endswith("_g") else "COMPLETE")
    if name.endswith("_h"):
        assert report["global_steps"] == 2
        assert all(value == 0.0 for pair in index["observed"]
                   for value in store.get_json(pair["response_id"])["rewards"])
    if name.endswith("_i"):
        assert report["global_steps"] == 2
        assert report["log_history"][0]["grad_norm"] > 0
        assert store.get_json(index["observed"][0]["response_id"])["rewards"] == [0.0, 1 / 7]


def test_preflight_archive_refuses_changed_reward_evidence(tmp_path: Path):
    copied = tmp_path / "preflight"
    shutil.copytree(ROOT / "grpo_bridge_h", copied)
    index = load_training_preflight_archive(copied)
    response_id = index["observed"][0]["response_id"]
    store = ContentAddressedStore(copied)
    path = store._path(response_id)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(IntegrityError):
        load_training_preflight_archive(copied)


def test_diagnostic_reward_must_match_raw_pass_count():
    evidence = {"evaluation": {"verdict": "REJECT", "counts": {"passed": 1}}}
    _validate_reward_evidence("REJECT", 1 / 7, evidence, "pytest_pass_fraction_v1", 7)
    with pytest.raises(IntegrityError, match="reward differs"):
        _validate_reward_evidence("REJECT", 2 / 7, evidence, "pytest_pass_fraction_v1", 7)
    with pytest.raises(IntegrityError, match="reward differs"):
        _validate_reward_evidence("REJECT", 1 / 7, evidence, "binary", 7)
