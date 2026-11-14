import json
from pathlib import Path

import pytest

from autoseal.repair import RepairOperator
from autoseal.repair_engine import (
    AdvertisedCapabilities, ProviderPrimitive, TypedRepairPlan, TypedRepairStep, VerifierPolicy,
)
from autoseal.revisions import RevisionManager, RevisionTransition
from autoseal.storage import ContentAddressedStore, IntegrityError


def fixture(tmp_path):
    store = ContentAddressedStore(tmp_path / "cas")
    manager = RevisionManager(tmp_path / "manager", store)
    policy = VerifierPolicy(candidate_files=("conftest.py", "solution.py"), verdict_owner="candidate_workspace")
    parent = manager.create(image_identity="sha256:" + "1" * 64, task=b"is_even",
                            policy=policy, artifacts={"tests/test_solution.py": b"trusted test bytes"})
    plan = TypedRepairPlan(parent_policy_identity=policy.identity, steps=(
        TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=("solution.py",)),
    ))
    child = manager.apply(parent, plan, AdvertisedCapabilities(primitives=(ProviderPrimitive.ARTIFACT_PROJECTION,)))
    return store, manager, parent, child


def test_revisions_restore_exact_artifacts_policy_and_cache_namespace(tmp_path):
    store, manager, parent, child = fixture(tmp_path)
    assert manager.active() is None
    manager.activate(parent, expected_active=None)
    manager.activate(child, expected_active=parent)
    assert manager.active() == child
    receipt_id = manager.rollback(expected_child=child)
    receipt = RevisionTransition.model_validate(store.get_json(receipt_id))
    assert receipt.action == "rollback" and receipt.before == child and receipt.after == parent
    assert receipt.cache_namespace == manager.cache_namespace(parent)
    assert receipt.cache_namespace != manager.cache_namespace(child)
    assert receipt.restored_artifacts == manager.load(parent).artifacts
    assert manager.active() == parent
    for identity in receipt.restored_artifacts.values():
        assert store.get_bytes(identity) == b"trusted test bytes"
    assert manager.load(child).parent_identity == parent


def test_stale_activation_and_rollback_cannot_overwrite_newer_state(tmp_path):
    _, manager, parent, child = fixture(tmp_path)
    manager.activate(parent, expected_active=None)
    with pytest.raises(IntegrityError, match="stale activation"):
        manager.activate(child, expected_active=None)
    with pytest.raises(IntegrityError, match="drift"):
        manager.rollback(expected_child=child)
    assert manager.active() == parent


def test_corrupt_managed_artifact_prevents_activation_before_pointer_write(tmp_path):
    store, manager, parent, child = fixture(tmp_path)
    manager.activate(parent, expected_active=None)
    pointer = (manager.root / "active.json").read_bytes()
    identity = next(iter(manager.load(parent).artifacts.values()))
    digest = identity[7:]
    (store.root / "objects" / digest[:2] / digest).write_bytes(b"changed verifier")
    with pytest.raises(IntegrityError, match="digest mismatch"):
        manager.activate(child, expected_active=parent)
    assert (manager.root / "active.json").read_bytes() == pointer


def test_pointer_tampering_and_symlinks_fail_closed(tmp_path):
    _, manager, parent, _ = fixture(tmp_path)
    manager.activate(parent, expected_active=None)
    path = manager.root / "active.json"
    body = json.loads(path.read_text())
    body["cache_namespace"] = "revision/some-other-result-cache"
    path.write_text(json.dumps(body))
    with pytest.raises(IntegrityError, match="transition evidence"):
        manager.active()
    path.unlink()
    path.symlink_to(tmp_path / "unowned-pointer")
    with pytest.raises(IntegrityError, match="symlink"):
        manager.active()


def test_root_cannot_rollback_and_unsafe_artifacts_are_rejected(tmp_path):
    _, manager, parent, _ = fixture(tmp_path)
    manager.activate(parent, expected_active=None)
    with pytest.raises(ValueError, match="no parent"):
        manager.rollback(expected_child=parent)
    with pytest.raises(ValueError, match="canonical"):
        manager.create(image_identity="sha256:" + "1" * 64, task=b"task",
                       policy=manager.load(parent).policy, artifacts={"../outside": b"bad"})
