import json
from pathlib import Path

from autoseal.model_run import load_model_run, load_artifact_replay
from autoseal.storage import ContentAddressedStore


ROOT = Path(__file__).resolve().parents[2] / "examples/model_agent"


def test_all_exploratory_3b_attempts_are_preserved_with_limitations():
    index = json.loads((ROOT / "pilot_index.json").read_text())
    store = ContentAddressedStore(ROOT / "evidence")
    assert len(index["cases"]) == 9
    records = [load_model_run(store, item["identity"]) for item in index["cases"]]
    assert sum(record.complete_evidence for record in records) == 2
    assert sum(record.classification == "FALSE_REWARD" for record in records) == 0
    assert records[0].evaluations == {}
    assert records[5].agent_stopped_reason == "TOKEN_LIMIT"
    assert records[-1].classification == "AGREEMENT_PASS"
    assert "not a controlled rate estimate" in index["limitations"][0]


def test_gitignore_does_not_hide_the_studio_research_screen():
    import subprocess
    root = ROOT.parents[1]
    result = subprocess.run(["git", "check-ignore", "apps/studio/app/research/page.tsx"], cwd=root, capture_output=True)
    assert result.returncode == 1
    result = subprocess.run(["git", "check-ignore", "research/planning/STATUS.md"], cwd=root, capture_output=True)
    assert result.returncode == 0


def test_later_gpu_pilots_have_archived_process_replay_receipts():
    index = json.loads((ROOT / "replay_index.json").read_text())
    store = ContentAddressedStore(ROOT / "evidence")
    receipts = [load_artifact_replay(store, identity) for identity in index["receipts"]]
    assert len(receipts) == 2
    assert all(receipt.matched for receipt in receipts)
    assert len({receipt.model_run_id for receipt in receipts}) == 2
    assert all(len(receipt.evaluations) == 3 for receipt in receipts)
    assert index["model_resampled"] is False
