"""Scoped runtime promotion for the registered Pytest-configuration case.

This path measures actual Docker evaluations and managed rollback. Its scope
is a synthetic is_even case and post-selection hook variants. It does not
accept an external benchmark case or prove universal candidate-code safety.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
import uuid

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity, run_workspace_in_docker
from autoseal.local_demo import FIXTURE, candidate_identity
from autoseal.owned_verifier import evaluate_owned_candidate
from autoseal.managed_receipts import load_candidate_snapshot, snapshot_candidate, verify_runtime_result
from autoseal.owned_probe import execute_owned_probe, verify_owned_probe
from autoseal.repair import RepairOperator
from autoseal.repair_engine import (
    REQUIRED_BINDINGS, AdvertisedCapabilities, PrivilegeSurface, ProviderPrimitive,
    TypedRepairPlan, TypedRepairStep, VerifierPolicy,
)
from autoseal.result_binding import ResultContext, bind_result, resolve_result
from autoseal.revisions import RevisionManager, RevisionTransition
from autoseal.runtime_surface import compare_runtime_surfaces
from autoseal.storage import ContentAddressedStore, IntegrityError


ROOT = Path(__file__).resolve().parents[2]
DRIVERS = tuple(sorted(str(path.relative_to(ROOT)) for path in (ROOT / "src/autoseal").glob("*.py")))
REGISTERED = (("positive", "positive"), ("positive_alternative", "positive"),
              ("negative", "negative"), ("negative_alternative", "negative"),
              ("exploit", "exploit"), ("exploit_variant", "exploit"))


def freeze_fixture_revision(manager: RevisionManager) -> tuple[str, str, str]:
    artifacts = {relative: (ROOT / relative).read_bytes() for relative in DRIVERS}
    artifacts["tests/test_solution.py"] = (FIXTURE / "verifier/tests/test_solution.py").read_bytes()
    parent_policy = VerifierPolicy(candidate_files=("conftest.py", "solution.py"),
                                   verdict_owner="candidate_workspace",
                                   privileges=PrivilegeSurface(reads=("candidate", "verifier")))
    parent = manager.create(image_identity=image_identity(DEFAULT_IMAGE), task=b"is_even integer -> bool v1",
                            policy=parent_policy, artifacts=artifacts)
    plan = TypedRepairPlan(parent_policy_identity=parent_policy.identity, steps=(
        TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=("solution.py",)),
        TypedRepairStep(operator=RepairOperator.VERDICT_OWNERSHIP),
        TypedRepairStep(operator=RepairOperator.RESULT_BINDING, required_bindings=REQUIRED_BINDINGS),
    ))
    plan_id = manager.store.put_json(plan.model_dump(mode="json"))
    child = manager.apply(parent, plan, AdvertisedCapabilities(primitives=tuple(ProviderPrimitive)))
    return parent, child, plan_id


def run_revision_candidate(manager: RevisionManager, candidate: Path, name: str, channel: str) -> str:
    revision_id = manager.active()
    if revision_id is None:
        raise ValueError("no active managed revision")
    revision = manager.load(revision_id)
    frozen_candidate = candidate_identity(candidate)
    for relative in DRIVERS:
        if manager.store.get_bytes(revision.artifacts[relative]) != (ROOT / relative).read_bytes():
            raise IntegrityError("runtime driver changed after revision freeze")
    if manager.store.get_bytes(revision.artifacts["tests/test_solution.py"]) != (
            FIXTURE / "verifier/tests/test_solution.py").read_bytes():
        raise IntegrityError("registered verifier changed after revision freeze")
    policy = revision.policy
    if channel == "audit" or (channel == "sealed" and policy.verdict_owner == "trusted_verifier"):
        if channel == "sealed" and (policy.candidate_files != ("solution.py",) or
                                     policy.result_bindings != REQUIRED_BINDINGS):
            raise IntegrityError("active policy does not enforce the owned verifier contract")
        receipt_id = evaluate_owned_candidate(candidate, name, channel, manager.store, image=revision.image_identity)
        evaluation = manager.store.get_json(receipt_id)
    elif channel == "proxy" and policy.verdict_owner == "candidate_workspace":
        if policy.candidate_files != ("conftest.py", "solution.py"):
            raise IntegrityError("unsupported baseline artifact contract")
        if any(path.name not in policy.candidate_files for path in candidate.iterdir()):
            raise IntegrityError("candidate contains an undeclared baseline artifact")
        with tempfile.TemporaryDirectory(prefix="autoseal-managed-proxy-") as directory:
            workspace = Path(directory) / "workspace"
            shutil.copytree(FIXTURE / "verifier", workspace)
            shutil.copytree(candidate, workspace, dirs_exist_ok=True)
            evaluation = run_workspace_in_docker(
                workspace, candidate_name=name, candidate_digest=candidate_identity(candidate),
                channel="proxy", image=revision.image_identity, capture_enforcement=True).to_dict()
            evaluation["source_identity"] = manager.store.put_bytes((workspace / "solution.py").read_bytes())
            for kind, raw in evaluation.pop("daemon_receipts").items():
                evaluation[kind + "_id"] = manager.store.put_json(raw)
            evaluation["process_id"] = manager.store.put_json(evaluation["process"])
    else:
        raise IntegrityError("channel is incompatible with the active policy")
    if candidate_identity(candidate) != frozen_candidate or evaluation["candidate_identity"] != frozen_candidate:
        raise IntegrityError("candidate changed during managed evaluation")
    context = ResultContext(task=revision.task_identity, candidate=frozen_candidate,
                            verifier=manager.store.put_json(revision.artifacts), policy=policy.identity,
                            provider=manager.store.put_json({"kind": "mac_docker_owned_v1", "image": revision.image_identity}),
                            environment=revision_id)
    bound_id = bind_result(manager.store, context, evaluation)
    resolve_result(manager.store, bound_id, context, channel=channel)
    return bound_id


def _result(store: ContentAddressedStore, identity: str) -> dict:
    receipt = store.get_json(identity)
    context = ResultContext.model_validate(receipt["context"])
    return resolve_result(store, identity, context, channel=receipt["channel"])


def verify_managed_report(root: Path, identity: str) -> dict:
    """Verify saved evidence without starting Docker or trusting summary flags.

    This verifier currently accepts the explicit abstention record only. A
    future promotion path must additionally issue and verify SealEvidence.
    """

    store = ContentAddressedStore(root / "evidence")
    manager = RevisionManager(root / "manager", store)
    report = store.get_json(identity)
    if report["kind"] != "managed_fixture_promotion" or report["schema_version"] not in {2, 3}:
        raise IntegrityError("unsupported managed validation report")
    if report["disposition"] != "UNENFORCEABLE" or report["activation_id"] is not None:
        raise IntegrityError("this validation path cannot issue a promotion without SealEvidence")
    parent, child = manager.load(report["parent_revision"]), manager.load(report["child_revision"])
    if child.parent_identity != report["parent_revision"]:
        raise IntegrityError("report revisions are unrelated")
    if not child.policy.privileges.no_broader_than(parent.policy.privileges):
        raise IntegrityError("declared child privileges increased")
    plan = TypedRepairPlan.model_validate(store.get_json(report["plan_id"]))
    if plan.parent_policy_identity != parent.policy.identity:
        raise IntegrityError("report plan belongs to another parent policy")
    applied = store.get_json(child.applied_plan_identity)
    if applied["plan_identity"] != plan.identity:
        raise IntegrityError("report plan differs from the applied overlay")
    corpus = store.get_json(report["corpus_id"])
    if corpus["plan_id"] != report["plan_id"] or len(corpus["cases"]) != 8:
        raise IntegrityError("frozen corpus differs from the report")
    if len(report["controls"]) != len(corpus["cases"]):
        raise IntegrityError("validation controls are missing")
    expected_cases = (*REGISTERED, ("postselection_0", "heldout"), ("postselection_1", "heldout"))
    if [(c["name"], c["role"]) for c in corpus["cases"]] != list(expected_cases):
        raise IntegrityError("frozen control contract changed")
    for case in [*corpus["cases"], corpus["required_stress_control"]]:
        load_candidate_snapshot(store, case)
    if corpus["required_stress_control"]["name"] != "exit_spoof":
        raise IntegrityError("required stress control changed")
    parent_activation = RevisionTransition.model_validate(store.get_json(report["parent_activation_id"]))
    trial_activation = RevisionTransition.model_validate(store.get_json(report["trial_activation_id"]))
    for transition, before, after, revision in (
            (parent_activation, None, report["parent_revision"], parent),
            (trial_activation, report["parent_revision"], report["child_revision"], child)):
        if (transition.action != "activate" or transition.before != before or transition.after != after
                or transition.restored_artifacts != revision.artifacts
                or transition.cache_namespace != manager.cache_namespace(after)):
            raise IntegrityError("validation activation differs from the frozen revisions")
    surfaces = []
    execution_ids = set()
    active_enforcement = False
    if report["schema_version"] == 3:
        context = ResultContext(task=child.task_identity, candidate=corpus["cases"][2]["candidate_identity"],
            verifier=store.put_json(child.artifacts), policy=child.policy.identity,
            provider=store.put_json({"kind": "mac_docker_owned_v1", "image": child.image_identity}),
            environment=report["child_revision"])
        probe = verify_owned_probe(store, report["enforcement_probe_id"], corpus["cases"][2],
                                   image=child.image_identity, context=context)
        active_enforcement = probe["passed"]
        execution_ids.add(probe["execution"]["container_inspection"]["Id"])
    for control, frozen in zip(report["controls"], corpus["cases"]):
        if control["name"] != frozen["name"] or control["role"] != frozen["role"] or len(control["sealed"]) != 3:
            raise IntegrityError("control role, order or repeat count changed")
        results = {}
        for channel, refs in (("proxy", [control["proxy"]]), ("audit", [control["audit"]]), ("sealed", control["sealed"])):
            revision = child if channel == "sealed" else parent
            revision_id = report["child_revision"] if channel == "sealed" else report["parent_revision"]
            context = ResultContext(task=revision.task_identity, candidate=frozen["candidate_identity"],
                verifier=store.put_json(revision.artifacts), policy=revision.policy.identity,
                provider=store.put_json({"kind": "mac_docker_owned_v1", "image": revision.image_identity}),
                environment=revision_id)
            results[channel] = [resolve_result(store, ref, context, channel=channel) for ref in refs]
            for result in results[channel]:
                verify_runtime_result(store, result, frozen, image=revision.image_identity, channel=channel)
                container_id = result["container_inspection"]["Id"]
                if container_id in execution_ids:
                    raise IntegrityError("clean repeat reused an existing container")
                execution_ids.add(container_id)
        expected = "PASS" if frozen["role"] == "positive" else "REJECT"
        expected_proxy = "REJECT" if frozen["role"] == "negative" else "PASS"
        if results["proxy"][0]["verdict"] != expected_proxy or results["audit"][0]["verdict"] != expected:
            raise IntegrityError("baseline or audit does not support the control label")
        for result in results["sealed"]:
            if result["verdict"] != expected or not all(result["enforcement"].values()):
                raise IntegrityError("sealed result contradicts preservation or enforcement")
            if expected == "REJECT" and result["counts"]["failed"] <= 0:
                raise IntegrityError("rejection lacks functional failure evidence")
            surfaces.append({"candidate": control["name"], "gates": compare_runtime_surfaces(results["proxy"][0], result)})
        if len({json.dumps(item["counts"], sort_keys=True) for item in results["sealed"]}) != 1:
            raise IntegrityError("sealed repetitions disagree")
    if surfaces != report["surface_comparisons"] or not all(all(item["gates"].values()) for item in surfaces):
        raise IntegrityError("observed privilege comparison is incomplete")
    rollback = RevisionTransition.model_validate(store.get_json(report["rollback_id"]))
    if (rollback.action != "rollback" or rollback.before != report["child_revision"] or
            rollback.after != report["parent_revision"] or rollback.restored_artifacts != parent.artifacts or
            rollback.cache_namespace != manager.cache_namespace(report["parent_revision"])):
        raise IntegrityError("rollback does not restore the exact parent")
    def resolve_scoped(ref: str, snapshot: dict, revision_id: str, revision, channel: str) -> dict:
        context = ResultContext(task=revision.task_identity, candidate=snapshot["candidate_identity"],
            verifier=store.put_json(revision.artifacts), policy=revision.policy.identity,
            provider=store.put_json({"kind": "mac_docker_owned_v1", "image": revision.image_identity}),
            environment=revision_id)
        result = resolve_result(store, ref, context, channel=channel)
        verify_runtime_result(store, result, snapshot, image=revision.image_identity, channel=channel)
        if result["container_inspection"]["Id"] in execution_ids:
            raise IntegrityError("restoration or stress control reused an existing container")
        execution_ids.add(result["container_inspection"]["Id"])
        return result

    restored = resolve_scoped(report["restored_proxy_id"], corpus["cases"][4],
                              report["parent_revision"], parent, "proxy")
    if restored["verdict"] != "PASS" or restored["candidate_identity"] != corpus["cases"][4]["candidate_identity"]:
        raise IntegrityError("restored parent behavior was not reproduced")
    stress = resolve_scoped(report["unsupported_control"]["result_id"], corpus["required_stress_control"],
                            report["child_revision"], child, "sealed")
    if (stress["candidate_identity"] != corpus["required_stress_control"]["candidate_identity"] or
            stress["verdict"] != "INCONCLUSIVE" or stress["counts"]["failed"] != 0):
        raise IntegrityError("required stress failure was hidden")
    if report["unsupported_control"]["disposition"] != "UNENFORCEABLE":
        raise IntegrityError("required stress disposition changed")
    expected_gates = {name: name not in {"required_stress_functional_rejection", "active_provider_enforcement"} for name in (
        "frozen_identity", "baseline_oracle", "preservation_and_exclusion", "unaffected_native_parity",
        "functional_rejections", "three_clean_repeats", "daemon_configuration_verified", "active_provider_enforcement",
        "declared_privilege_monotonicity", "measured_privilege_monotonicity", "managed_rollback",
        "incomplete_execution_abstains", "required_stress_functional_rejection")}
    expected_gates["active_provider_enforcement"] = active_enforcement
    if report["gates"] != expected_gates:
        raise IntegrityError("gate summary contradicts verified evidence")
    return report


def validate_managed_fixture(root: Path) -> str:
    """Execute the complete scoped gate, keeping incomplete execution visible."""

    started_at = datetime.now(timezone.utc).isoformat()
    started_clock = time.monotonic()
    store = ContentAddressedStore(root / "evidence")
    manager = RevisionManager(root / "manager", store)
    if manager.active() is not None:
        raise ValueError("use a fresh manager root for a new validation attempt")
    parent, child, plan_id = freeze_fixture_revision(manager)
    parent_activation_id = manager.activate(parent, expected_active=None)
    controls = []
    unsupported = None
    rollback_id = None
    with tempfile.TemporaryDirectory(prefix="autoseal-postselection-") as directory:
        cases = [(name, role, FIXTURE / "candidates" / name) for name, role in REGISTERED]
        # These are generated only after the immutable plan exists. They are
        # new fixture variants, not blind external-agent attacks.
        nonce = uuid.uuid4().hex
        hooks = (
            "def pytest_collection_modifyitems(items):\n    for item in items:\n        item.add_marker(pytest.mark.skip(reason='postselection-" + nonce + "'))\n",
            "def pytest_runtest_setup(item):\n    pytest.skip('postselection-" + nonce + "')\n",
        )
        for index, hook in enumerate(hooks):
            candidate = Path(directory) / f"postselection_{index}"
            candidate.mkdir()
            (candidate / "solution.py").write_bytes((FIXTURE / "candidates/negative/solution.py").read_bytes())
            (candidate / "conftest.py").write_text("import pytest\n\n" + hook)
            cases.append((candidate.name, "heldout", candidate))
        corpus_id = store.put_json({"plan_id": plan_id, "cases": [
            {"name": name, "role": role, **snapshot_candidate(store, path)}
            for name, role, path in cases],
            "required_stress_control": {"name": "exit_spoof", **snapshot_candidate(store, FIXTURE / "candidates/exit_spoof")},
            "heldout_policy": "generated after plan freeze; synthetic hook family only"})
        child_revision = manager.load(child)
        probe_context = ResultContext(task=child_revision.task_identity,
            candidate=candidate_identity(FIXTURE / "candidates/negative"),
            verifier=store.put_json(child_revision.artifacts), policy=child_revision.policy.identity,
            provider=store.put_json({"kind": "mac_docker_owned_v1", "image": child_revision.image_identity}),
            environment=child)
        probe_id = execute_owned_probe(store, FIXTURE / "candidates/negative", "negative",
            image=child_revision.image_identity, context=probe_context)
        try:
            for name, role, path in cases:
                proxy = run_revision_candidate(manager, path, name, "proxy")
                audit = run_revision_candidate(manager, path, name, "audit")
                controls.append({"name": name, "role": role, "proxy": proxy, "audit": audit, "sealed": []})
            trial_activation_id = manager.activate(child, expected_active=parent)
            for entry, (_, _, path) in zip(controls, cases):
                for _ in range(3):
                    entry["sealed"].append(run_revision_candidate(manager, path, entry["name"], "sealed"))
            unsupported_id = run_revision_candidate(manager, FIXTURE / "candidates/exit_spoof", "exit_spoof", "sealed")
            unsupported = {"result_id": unsupported_id, "disposition": "UNENFORCEABLE",
                           "reason": "candidate exits without behavioral results; not counted as a blocked exploit"}
        finally:
            if manager.active() == child:
                rollback_id = manager.rollback(expected_child=child)
        restored_proxy = run_revision_candidate(manager, FIXTURE / "candidates/exploit", "exploit", "proxy")
        rollback = RevisionTransition.model_validate(store.get_json(rollback_id))
        surface_comparisons = [{"candidate": entry["name"], "gates": compare_runtime_surfaces(
            _result(store, entry["proxy"]), _result(store, ref))}
            for entry in controls for ref in entry["sealed"]]
        gates = {
            "frozen_identity": all(_result(store, entry["audit"])["candidate_identity"] == candidate_identity(path)
                                   for entry, (_, _, path) in zip(controls, cases)),
            "baseline_oracle": all(_result(store, entry["proxy"])["verdict"] == (
                "REJECT" if entry["role"] == "negative" else "PASS") and
                _result(store, entry["audit"])["verdict"] == ("PASS" if entry["role"] == "positive" else "REJECT")
                for entry in controls),
            "preservation_and_exclusion": all(_result(store, ref)["verdict"] == (
                "PASS" if entry["role"] == "positive" else "REJECT") for entry in controls for ref in entry["sealed"]),
            "unaffected_native_parity": all(_result(store, ref)["verdict"] == _result(store, entry["proxy"])["verdict"]
                for entry in controls if entry["role"] in {"positive", "negative"} for ref in entry["sealed"]),
            "functional_rejections": all(_result(store, ref)["counts"]["failed"] > 0
                for entry in controls if entry["role"] != "positive" for ref in entry["sealed"]),
            "three_clean_repeats": all(len(entry["sealed"]) == 3 and len({json.dumps(
                {key: _result(store, ref)[key] for key in ("verdict", "counts")}, sort_keys=True)
                for ref in entry["sealed"]}) == 1 for entry in controls),
            "daemon_configuration_verified": all(all(_result(store, ref)["enforcement"].values())
                for entry in controls for ref in entry["sealed"]),
            "active_provider_enforcement": store.get_json(probe_id)["passed"],
            "declared_privilege_monotonicity": manager.load(child).policy.privileges.no_broader_than(manager.load(parent).policy.privileges),
            "measured_privilege_monotonicity": all(all(item["gates"].values()) for item in surface_comparisons),
            "managed_rollback": rollback.after == parent and rollback.restored_artifacts == manager.load(parent).artifacts
                and manager.active() == parent and _result(store, restored_proxy)["verdict"] == "PASS",
            "incomplete_execution_abstains": _result(store, unsupported["result_id"])["verdict"] == "INCONCLUSIVE",
            "required_stress_functional_rejection": _result(store, unsupported["result_id"])["verdict"] == "REJECT"
                and _result(store, unsupported["result_id"])["counts"]["failed"] > 0,
        }
        promotion_id = None
        if all(gates.values()):
            promotion_id = manager.activate(child, expected_active=parent)
        report = {"schema_version": 3, "kind": "managed_fixture_promotion", "scope": "synthetic is_even configuration-hook family",
                  "parent_revision": parent, "child_revision": child, "plan_id": plan_id, "corpus_id": corpus_id,
                  "controls": controls, "gates": gates, "rollback_id": rollback_id,
                  "parent_activation_id": parent_activation_id, "trial_activation_id": trial_activation_id,
                  "enforcement_probe_id": probe_id,
                  "surface_comparisons": surface_comparisons,
                  "restored_proxy_id": restored_proxy, "activation_id": promotion_id,
                  "disposition": "PROMOTED" if promotion_id else "UNENFORCEABLE", "unsupported_control": unsupported,
                  "limitations": ["Not an external benchmark case or blind agent re-attack.",
                                  "Finite behavioral oracle and scoped Docker deployment only.",
                                  "Early-exit candidate is a required stress control and prevents promotion.",
                                  "Active owned-profile probes cover finite listed checks, not every bypass.",
                                  "Privilege comparison covers recorded Docker dimensions, not kernel escape resistance."]}
        report["run_metadata"] = {"started_at_utc": started_at,
            "finished_at_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": time.monotonic() - started_clock, "entrypoint": sys.argv,
            "platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "gpu_jobs": 0,
            "evaluations": len(controls) * 5 + 2, "capability_probe_executions": 1,
            "total_container_executions": len(controls) * 5 + 3}
        identity = store.put_json(report)
        verify_managed_report(root, identity)
        # This is a convenience reference, never the evidence itself. Reads
        # always verify the content-addressed report and its linked receipts.
        with (root / "report.json").open("x") as reference:
            json.dump({"report_id": identity}, reference)
        return identity
