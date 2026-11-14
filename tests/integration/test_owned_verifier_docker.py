from pathlib import Path

import pytest

from autoseal.owned_verifier import evaluate_owned_fixture
from autoseal.storage import ContentAddressedStore


pytestmark = pytest.mark.docker


@pytest.mark.parametrize("candidate,expected", [
    ("positive", "PASS"), ("positive_alternative", "PASS"),
    ("negative", "REJECT"), ("negative_alternative", "REJECT"),
    ("exploit", "REJECT"), ("exploit_variant", "REJECT"), ("exploit_holdout", "REJECT"),
    ("exit_spoof", "INCONCLUSIVE"),
])
def test_owned_verifier_keeps_candidate_outputs_untrusted(tmp_path: Path, candidate, expected):
    store = ContentAddressedStore(tmp_path / "evidence")
    identity = evaluate_owned_fixture(candidate, "sealed", store)
    result = store.get_json(identity)
    assert result["verdict"] == expected
    assert all(result["enforcement"].values())
    assert result["owner"] == "trusted_manager"
    assert store.get_json(result["process_id"]) == result["process"]
    if expected == "REJECT":
        assert result["counts"]["failed"] > 0
