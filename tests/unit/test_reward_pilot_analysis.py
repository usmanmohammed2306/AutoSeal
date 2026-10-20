import json

import pytest

from autoseal.reward_bridge import RewardBridgeManifest, RewardRequest, RewardResponse
from autoseal.storage import ContentAddressedStore, IntegrityError
from scripts.analyze_reward_pilot import analyze


def test_analysis_requires_complete_paired_receipts_and_reports_no_improvement(tmp_path):
    store = ContentAddressedStore(tmp_path / "store")
    training = {"scope": "GRPO_BRIDGE_SMOKE_ONLY", "model_snapshot_revision": "fixed-revision"}
    experiment = store.put_json(training)
    task = store.put_bytes(b"task")
    manifest = RewardBridgeManifest(experiment_id=experiment, task_id=task,
                                    verifier_identity=store.put_bytes(b"verifier"),
                                    image_identity=store.put_bytes(b"image"),
                                    seeds=(11,), max_batches_per_seed=1, batch_size=1)
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    config_id = store.put_json({"schema_version": 1, "training_configuration": training,
                                "bridge_manifest_id": manifest_id,
                                "bridge_manifest": manifest.model_dump(mode="json")})
    output = tmp_path / "output"
    for arm, outcome, reward in (("vulnerable", "PASS", 1.0), ("sealed", "REJECT", 0.0)):
        request = RewardRequest(bridge_manifest_id=manifest_id, experiment_id=experiment,
                                task_id=task, arm=arm, seed=11, batch=0,
                                completions=('{}',))
        request_id = store.put_json(request.model_dump(mode="json"))
        response = RewardResponse(request_id=request_id, bridge_manifest_id=manifest_id,
                                  status="COMPLETE", rewards=[reward], outcomes=[outcome],
                                  evidence_ids=[store.put_json({"kind": "test_evidence"})])
        response_id = store.put_json(response.model_dump(mode="json"))
        folder = output / f"{arm}_11"
        (folder / "adapter").mkdir(parents=True)
        (folder / "adapter" / "adapter_model.safetensors").write_bytes(arm.encode())
        (folder / "result.json").write_text(json.dumps({
            "arm": arm, "seed": 11, "configuration_id": config_id, "status": "COMPLETE",
            "global_steps": 1, "batch_receipts": [{"batch": 0, "request_id": request_id,
                                                    "response_id": response_id}],
            "log_history": [{"reward_std": 0.0}], "training_loss": 0.0,
            "gpu_name": "test GPU", "peak_gpu_bytes": 42,
        }))
    summary = analyze(store, output, config_id)
    assert summary["paired_conditions_complete"]
    assert not summary["nonzero_within_batch_reward_variance"]
    assert not summary["downstream_improvement_established"]
    assert [item["reward_sum"] for item in summary["conditions"]] == [1.0, 0.0]
    target = output / "sealed_11/result.json"
    wrong = json.loads(target.read_text())
    wrong["seed"] = 33
    target.write_text(json.dumps(wrong))
    with pytest.raises(IntegrityError, match="condition"):
        analyze(store, output, config_id)
