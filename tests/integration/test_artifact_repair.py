"""Real Docker data-task repair and admission, separate from function fixtures."""

import copy
import json

import pytest

from autoseal.artifact_cases import registered_tasks
from autoseal.artifact_pipeline import (deployment_manager, evaluate_artifact, promote_artifact,
    resolve_artifact, rollback_artifact, validate_artifact_case, verify_artifact_validation)
from autoseal.seal import verify_seal
from autoseal.storage import ContentAddressedStore, IntegrityError


pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def validated(tmp_path_factory):
    root = tmp_path_factory.mktemp("artifact-repair")
    identity = validate_artifact_case(root, registered_tasks()["artifact-skip_hook-0"])
    return root, identity


def test_actual_preservation_admission_and_deployment_rollback(validated):
    root, identity = validated
    store = ContentAddressedStore(root / "evidence")
    report = verify_artifact_validation(store, identity)
    assert all(report["gates"].values()), report["gates"]
    manager = deployment_manager(root)
    assert manager.active() == report["parent_revision"]
    with pytest.raises(IntegrityError, match="admission"):
        manager.activate(report["child_revision"], expected_active=report["parent_revision"])
    promoted = promote_artifact(root, identity)
    assert promoted["disposition"] == "PROMOTED"
    seal = verify_seal(store, promoted["seal_evidence_id"], child_revision=report["child_revision"])
    assert seal.validation_identity == identity
    assert manager.active() == report["child_revision"]
    assert promote_artifact(root, identity) == promoted
    control = store.get_json(report["case_id"])["controls"][4]
    ref = evaluate_artifact(store, report["case_id"], control["candidate_id"], manager.active(), "sealed")
    assert resolve_artifact(store, ref, case_id=report["case_id"], candidate_id=control["candidate_id"],
        revision_id=manager.active(), channel="sealed")["verdict"] == "REJECT"
    rollback_id = rollback_artifact(root, report["child_revision"])
    assert store.get_json(rollback_id)["after"] == report["parent_revision"]
    assert manager.active() == report["parent_revision"]
    with pytest.raises(IntegrityError):
        rollback_artifact(root, report["child_revision"])
    assert promote_artifact(root, identity)["seal_evidence_id"] == promoted["seal_evidence_id"]


@pytest.mark.parametrize("change", ["gate", "repeat", "search", "plan", "rollback", "split"])
def test_forged_validation_cannot_be_promoted(validated, change):
    root, identity = validated
    store = ContentAddressedStore(root / "evidence")
    forged = copy.deepcopy(store.get_json(identity))
    if change == "gate":
        forged["gates"]["positives_preserved"] = False
    elif change == "repeat":
        forged["controls"][0]["sealed"][1] = forged["controls"][0]["sealed"][0]
    elif change == "search":
        search = store.get_json(forged["search_id"])
        search["search"][0]["preserved"] = True
        forged["search_id"] = store.put_json(search)
    elif change == "plan":
        search = store.get_json(forged["search_id"])
        forged["plan_id"] = search["search"][0]["plan_id"]
    elif change == "rollback":
        forged["rollback_id"] = forged["restored_proxy"]
    else:
        case = store.get_json(forged["case_id"])
        case["controls"][-1]["role"] = "development"
        forged["case_id"] = store.put_json(case)
    with pytest.raises((IntegrityError, ValueError)):
        promote_artifact(root, store.put_json(forged))
