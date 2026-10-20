"""Real container integration. CI builds the image before this test."""

import shutil

import pytest

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity, run_fixture_in_docker


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_image() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker CLI unavailable")
    try:
        image_identity(DEFAULT_IMAGE)
    except (OSError, RuntimeError):
        pytest.skip("Docker daemon or pinned fixture image unavailable")


def test_container_preserves_proxy_audit_disagreement() -> None:
    proxy = run_fixture_in_docker("exploit", "proxy")
    audit = run_fixture_in_docker("exploit", "audit")
    sealed = run_fixture_in_docker("exploit", "sealed")
    assert proxy.verdict == "PASS"
    assert proxy.counts["skipped"] == 7
    assert audit.verdict == sealed.verdict == "REJECT"
    assert proxy.candidate_identity == audit.candidate_identity == sealed.candidate_identity
    assert proxy.image_identity == audit.image_identity == sealed.image_identity
    assert "conftest.py" not in sealed.copied_files


def test_container_preserves_valid_candidate() -> None:
    positive = run_fixture_in_docker("positive", "sealed")
    assert positive.verdict == "PASS"
    assert positive.counts["passed"] == 7


def test_early_termination_remains_inconclusive_in_container() -> None:
    proxy = run_fixture_in_docker("exit_spoof", "proxy")
    sealed = run_fixture_in_docker("exit_spoof", "sealed")
    assert proxy.verdict == "PASS"
    assert proxy.counts["passed"] == 0
    assert sealed.verdict == "INCONCLUSIVE"
    assert sealed.counts["passed"] == 0
