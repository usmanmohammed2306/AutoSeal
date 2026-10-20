from pathlib import Path
import json
import shutil

import pytest

from autoseal.reward_bridge import RewardRequest, RewardResponse
from autoseal.storage import ContentAddressedStore, IntegrityError
from autoseal.training_pilot_archive import load_training_pilot_archive


def test_saved_parser_fix_pilot_keeps_all_passes_and_zero_gradient_signal():
    root = Path(__file__).resolve().parents[2] / "examples/training_pilot/grpo_bridge_e"
    index = load_training_pilot_archive(root)
    assert index["missing_frozen_source_files"] == []
    assert len(index["reports"]) == 6
    assert all(row["outcomes"] == {"PASS": 4} for row in index["summary"]["conditions"])
    assert not index["summary"]["nonzero_within_batch_reward_variance"]
    assert not index["summary"]["downstream_improvement_established"]


def test_semver_pilot_archives_frozen_verifier_and_bound_results():
    root = Path(__file__).resolve().parents[2] / "examples/training_pilot/grpo_bridge_f"
    index = load_training_pilot_archive(root)
    assert index["missing_frozen_source_files"] == []
    assert set(index["verifier_files"]) == {"tests/test_solution.py"}
    assert index["summary"]["identical_paired_adapter_seeds"] == [11, 22, 33]
    assert not index["summary"]["nonzero_within_batch_reward_variance"]


def test_one_seed_diagnostic_pair_has_gradients_but_no_arm_difference():
    root = Path(__file__).resolve().parents[2] / "examples/training_pilot/grpo_bridge_i_paired"
    index = load_training_pilot_archive(root)
    assert len(index["reports"]) == 2
    assert index["summary"]["nonzero_within_batch_reward_variance"]
    assert index["summary"]["identical_paired_adapter_seeds"] == [11]
    assert {row["reward_sum"] for row in index["summary"]["conditions"]} == {1 / 7}
    assert all(row["reward_stds"][0] > 0 for row in index["summary"]["conditions"])
    assert not index["summary"]["downstream_improvement_established"]


def test_archive_rejects_a_reshaped_reward_summary(tmp_path):
    original = Path(__file__).resolve().parents[2] / "examples/training_pilot/grpo_bridge_d"
    copy = tmp_path / "archive"
    shutil.copytree(original, copy)
    index = json.loads((copy / "index.json").read_text())
    index["summary"]["conditions"][0]["reward_sum"] = 1.0
    (copy / "index.json").write_text(json.dumps(index))
    with pytest.raises(IntegrityError, match="summary disagrees"):
        load_training_pilot_archive(copy)


def test_saved_zero_signal_pilot_archive_is_complete_and_honest():
    root = Path(__file__).resolve().parents[2] / "examples/training_pilot/grpo_bridge_d"
    index = load_training_pilot_archive(root)
    store = ContentAddressedStore(root)
    config = store.get_json(index["configuration_id"])
    assert config["training_configuration"]["scope"] == "GRPO_BRIDGE_SMOKE_ONLY"
    assert index["summary"]["paired_conditions_complete"]
    assert not index["summary"]["nonzero_within_batch_reward_variance"]
    assert not index["summary"]["downstream_improvement_established"]
    assert len(index["reports"]) == 6
    for name, identity in index["reports"].items():
        report = store.get_json(identity)
        assert report["status"] == "COMPLETE" and report["global_steps"] == 2
        assert name == f'{report["arm"]}_{report["seed"]}'
        for pair in report["batch_receipts"]:
            request = RewardRequest.model_validate(store.get_json(pair["request_id"]))
            response = RewardResponse.model_validate(store.get_json(pair["response_id"]))
            assert response.request_id == pair["request_id"]
            assert len(request.completions) == len(response.evidence_ids) == 2
            assert response.outcomes == ["INVALID_OUTPUT", "INVALID_OUTPUT"]
            for evidence_id in response.evidence_ids:
                evidence = store.get_json(evidence_id)
                store.get_bytes(evidence["completion_id"])
