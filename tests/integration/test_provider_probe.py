import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.provider_probe import probe_docker_provider
from autoseal.storage import ContentAddressedStore

pytestmark = pytest.mark.docker


def test_active_docker_limits_are_observed_not_just_advertised(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("Docker image or daemon unavailable")
    store = ContentAddressedStore(tmp_path)
    result = probe_docker_provider(store)
    assert result["passed"], result
    assert all(result["gates"].values())
    process = store.get_json(result["process_evidence_id"])
    assert process["exit_code"] == 0
    assert store.get_bytes(result["probe_code_id"])
    assert "No disk quota" in result["limitations"][2]
