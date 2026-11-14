"""Evidence-driven artifact repair, preservation, admission and rollback.

The registered adapter grades finite fixed-output tasks without importing
candidate code into the owned verifier. Seeded cases stay separately labeled.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Optional
import uuid

from autoseal.artifact_cases import (ArtifactTask, OWNED_WORKER, PROXY_WORKER, audit_expected,
    freeze_case, load_case, proxy_expected)
from autoseal.artifact_runtime import execute_bundle, freeze_files, load_files, verify_bundle_execution
from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.evaluation import TestCounts
from autoseal.local_demo import _counts
from autoseal.owned_probe import PROBE_CODE, interpret_probe
from autoseal.repair import RepairOperator
from autoseal.repair_engine import (REQUIRED_BINDINGS, AdvertisedCapabilities, PrivilegeSurface,
    ProviderPrimitive, TypedRepairPlan, TypedRepairStep)
from autoseal.repair_engine import VerifierPolicy
from autoseal.result_binding import ResultContext, bind_result, resolve_result
from autoseal.revisions import RevisionManager, RevisionTransition
from autoseal.seal import SealEvidence, verify_seal
from autoseal.storage import ContentAddressedStore, IntegrityError, VerificationSnapshot, canonical_json


ROOT = Path(__file__).resolve().parents[2]


def _manager(store: ContentAddressedStore) -> RevisionManager:
    # Loading immutable revisions does not need a mutable deployment pointer.
    return RevisionManager(store.root.parent / "revision-reader", store)


def deployment_manager(root: Path) -> RevisionManager:
    store = ContentAddressedStore(root / "evidence")
    def admit(proof, child):
        verify_seal(store, proof, child_revision=child)
        _assert_runtime(store, _manager(store).load(child))
    return RevisionManager(root / "deployment", store, admission_verifier=admit)


def _assert_runtime(store, revision):
    for name, ref in revision.artifacts.items():
        if name.startswith("src/autoseal/") and (ROOT / name).read_bytes() != store.get_bytes(ref):
            raise IntegrityError("runtime source changed since repair validation")


def _context(store, revision_id, revision, candidate_id) -> ResultContext:
    return ResultContext(task=revision.task_identity, candidate=candidate_id,
        verifier=store.put_json(revision.artifacts), policy=revision.policy.identity,
        provider=store.put_json({"kind": "artifact_docker_v1", "image": revision.image_identity}),
        environment=revision_id)


def _inputs(store, case, task, candidate_id, policy, channel):
    original = load_files(store, candidate_id)
    if channel == "audit":
        selected = {name: data for name, data in original.items() if name == "answer.json"}
        worker, payload = OWNED_WORKER, {"expected": audit_expected(task), "oracle": "independent_reference_v1"}
    else:
        selected = {name: data for name, data in original.items() if name in policy.candidate_files}
        if policy.verdict_owner == "trusted_verifier":
            worker, payload = OWNED_WORKER, {"expected": proxy_expected(task), "oracle": "sealed_contract_v1"}
        else:
            selected = {"test_output.py": store.get_bytes(case["proxy_test_id"]), **selected}
            worker, payload = PROXY_WORKER, {"mode": task.proxy_mode}
    if not selected:
        # A missing deliverable is still a defined data-task result. This
        # trusted marker prevents an empty runtime bundle, not a fake answer.
        selected = {"missing-output.txt": b"No approved output artifact was submitted.\n"}
    return freeze_files(store, selected), worker, payload


def _outcome(process, *, owned):
    if process["stdout_truncated"] or process["stderr_truncated"]:
        raise IntegrityError("truncated artifact evaluation cannot be authoritative")
    if owned:
        if process["status"] != "exited_zero":
            raise IntegrityError("owned artifact verifier did not complete")
        result = json.loads(process["stdout"])
        if set(result) != {"verdict", "counts"} or result["verdict"] not in {"PASS", "REJECT"}:
            raise IntegrityError("owned artifact verifier returned an invalid protocol")
        counts = TestCounts.model_validate(result["counts"])
        if counts.skipped or counts.errors or counts.passed + counts.failed != 1:
            raise IntegrityError("owned artifact verifier did not check the output obligation")
        if (result["verdict"] == "PASS") != (counts.passed == 1):
            raise IntegrityError("owned artifact verdict contradicts its obligation count")
        return result
    counts = _counts(process["stdout"])
    if process["status"] == "exited_zero":
        verdict = "PASS"
    elif process["status"] == "exited_nonzero" and counts["failed"]:
        verdict = "REJECT"
    else:
        raise IntegrityError("proxy failed without a decisive task result")
    return {"verdict": verdict, "counts": counts}


def evaluate_artifact(store: ContentAddressedStore, case_id: str, candidate_id: str,
                       revision_id: str, channel: str) -> str:
    if channel not in {"proxy", "sealed", "audit"}:
        raise ValueError("unknown artifact channel")
    case, task = load_case(store, case_id)
    revision = _manager(store).load(revision_id)
    if store.get_json(revision.task_identity) != task.model_dump(mode="json"):
        raise IntegrityError("artifact revision belongs to another task")
    _assert_runtime(store, revision)
    bundle, worker, payload = _inputs(store, case, task, candidate_id, revision.policy, channel)
    execution_id = execute_bundle(store, bundle, image=revision.image_identity, worker=worker, payload=payload)
    execution = verify_bundle_execution(store, execution_id, bundle_id=bundle,
        image=revision.image_identity, worker=worker, payload=payload)
    result = {"candidate_identity": candidate_id, "channel": channel, "execution_id": execution_id,
        "case_id": case_id, "process": execution["process"],
        **_outcome(execution["process"], owned=channel == "audit" or revision.policy.verdict_owner == "trusted_verifier")}
    return bind_result(store, _context(store, revision_id, revision, candidate_id), result)


def resolve_artifact(store, identity, *, case_id, candidate_id, revision_id, channel):
    case, task = load_case(store, case_id)
    revision = _manager(store).load(revision_id)
    result = resolve_result(store, identity, _context(store, revision_id, revision, candidate_id), channel=channel)
    if result["case_id"] != case_id:
        raise IntegrityError("artifact result belongs to another case")
    bundle, worker, payload = _inputs(store, case, task, candidate_id, revision.policy, channel)
    execution = verify_bundle_execution(store, result["execution_id"], bundle_id=bundle,
        image=revision.image_identity, worker=worker, payload=payload)
    observed = _outcome(execution["process"], owned=channel == "audit" or revision.policy.verdict_owner == "trusted_verifier")
    if (canonical_json(result["process"]) != canonical_json(execution["process"])
            or any(result[key] != observed[key] for key in ("verdict", "counts"))):
        raise IntegrityError("artifact summary contradicts raw execution")
    return {**result, "inspection": execution["inspection"], "bundle_id": bundle}


def _plans(parent_policy, causal_files):
    if not causal_files or "answer.json" in causal_files:
        raise IntegrityError("architectural proposal needs an isolated non-answer influence path")
    ownership = TypedRepairStep(operator=RepairOperator.VERDICT_OWNERSHIP)
    binding = TypedRepairStep(operator=RepairOperator.RESULT_BINDING, required_bindings=REQUIRED_BINDINGS)
    # The unsafe cut retains code but loses the required output. Its rejection
    # must come from positive preservation, not an operator-name denylist.
    return [TypedRepairPlan(parent_policy_identity=parent_policy.identity, steps=(
        TypedRepairStep(operator=RepairOperator.ARTIFACT_PROJECTION, allowed_files=(name,)), ownership, binding))
        for name in ("solution.py", "answer.json")] + [TypedRepairPlan(
            parent_policy_identity=parent_policy.identity, steps=(ownership, binding))]


def _expected(control):
    return "PASS" if control["role"] == "positive" else "REJECT"


def _freeze_revision(store, case_id, image):
    case, task = load_case(store, case_id)
    names = sorted({name for c in case["controls"] for name in load_files(store, c["candidate_id"])})
    policy = VerifierPolicy(candidate_files=tuple(names), verdict_owner="candidate_workspace",
                           privileges=PrivilegeSurface(reads=("candidate", "verifier")))
    artifacts = {str(path.relative_to(ROOT)): path.read_bytes() for path in sorted((ROOT / "src/autoseal").glob("*.py"))}
    artifacts["verifier/test_output.py"] = store.get_bytes(case["proxy_test_id"])
    return _manager(store).create(image_identity=image, task=canonical_json(task.model_dump(mode="json")),
                                  policy=policy, artifacts=artifacts)


def validate_artifact_case(root: Path, task: ArtifactTask, *, progress=None) -> str:
    """Run development search, then committed held-outs and promotion gates."""
    root.mkdir(parents=True, exist_ok=True)
    store = ContentAddressedStore(root / "evidence")
    manager = deployment_manager(root)
    if manager.active() is not None:
        raise ValueError("use a fresh artifact validation root")
    case_id = freeze_case(store, task)
    def notify(stage, payload=None):
        if progress:
            progress(stage, payload or {})
    notify("CASE_FROZEN", {"case_id": case_id})
    case, task = load_case(store, case_id)
    image = image_identity(DEFAULT_IMAGE)
    parent = _freeze_revision(store, case_id, image)
    manager.activate(parent, expected_active=None)
    baseline = []
    for control in case["controls"]:
        notify("BASELINE", {"control": control["name"]})
        baseline.append({"name": control["name"], "candidate_id": control["candidate_id"],
            **{channel: evaluate_artifact(store, case_id, control["candidate_id"], parent, channel)
               for channel in ("proxy", "audit")}})
    witness_control = case["controls"][4]
    original = load_files(store, witness_control["candidate_id"])
    kept = dict(original)
    interventions = [{"candidate_id": witness_control["candidate_id"], "proxy": baseline[4]["proxy"]}]
    for name in sorted(set(original) - {"answer.json"}):
        notify("MINIMIZING", {"removed_file": name})
        trial = {key: data for key, data in kept.items() if key != name}
        candidate_id = freeze_files(store, trial)
        result_id = evaluate_artifact(store, case_id, candidate_id, parent, "proxy")
        interventions.append({"candidate_id": candidate_id, "proxy": result_id})
        if resolve_artifact(store, result_id, case_id=case_id, candidate_id=candidate_id,
                            revision_id=parent, channel="proxy")["verdict"] == "PASS":
            kept = trial
    witness_id = freeze_files(store, kept)
    causal_files = sorted(set(kept) - {"answer.json"})
    for name in causal_files:
        trial_id = freeze_files(store, {key: data for key, data in kept.items() if key != name})
        interventions.append({"candidate_id": trial_id,
            "proxy": evaluate_artifact(store, case_id, trial_id, parent, "proxy")})
    graph_id = store.put_json({"kind": "artifact_influence_graph", "case_id": case_id,
        "resolution": "file_interventions", "causal_files": causal_files,
        "interventions": interventions,
        "limitation": "File-removal effects are measured; internal hook/import events are not traced."})
    parent_revision = _manager(store).load(parent)
    search = []
    for plan in _plans(parent_revision.policy, causal_files):
        plan_id = store.put_json(plan.model_dump(mode="json"))
        notify("SEARCHING", {"plan_id": plan_id})
        child = _manager(store).apply(parent, plan, AdvertisedCapabilities(primitives=tuple(ProviderPrimitive)))
        outcomes = [evaluate_artifact(store, case_id, control["candidate_id"], child, "sealed")
                    for control in case["controls"] if control["role"] != "heldout"]
        preserved = all(resolve_artifact(store, ref, case_id=case_id, candidate_id=control["candidate_id"],
            revision_id=child, channel="sealed")["verdict"] == _expected(control)
            for ref, control in zip(outcomes, case["controls"][:6]))
        search.append({"plan_id": plan_id, "child_revision": child, "development": outcomes,
                       "preserved": preserved})
    eligible = [row for row in search if row["preserved"]]
    if not eligible:
        raise IntegrityError("registered artifact case has no preservation-safe repair")
    selected = min(eligible, key=lambda row: (len(_manager(store).load(row["child_revision"]).policy.candidate_files),
                                             len(store.get_json(row["plan_id"])["steps"]), row["plan_id"]))
    selection_id = store.put_json({"case_id": case_id, "search": search,
                                  "plan_id": selected["plan_id"], "child_revision": selected["child_revision"]})
    child = selected["child_revision"]
    controls = []
    for control in case["controls"]:
        notify("PRESERVATION", {"control": control["name"], "role": control["role"]})
        controls.append({"name": control["name"], "candidate_id": control["candidate_id"],
            "sealed": [evaluate_artifact(store, case_id, control["candidate_id"], child, "sealed") for _ in range(3)]})
    revision = _manager(store).load(child)
    probe_bundle, _, _ = _inputs(store, case, task, case["controls"][2]["candidate_id"], revision.policy, "sealed")
    probe_payload = {"nonce": uuid.uuid4().hex}
    notify("PROBING")
    probe_id = execute_bundle(store, probe_bundle, image=image, worker=PROBE_CODE, payload=probe_payload)
    # Rollback is exercised in a separate validation pointer. The deployed
    # pointer remains at the parent until independently verified admission.
    trial = RevisionManager(root / "validation-trial", store)
    notify("ROLLBACK_VALIDATION")
    trial.activate(parent, expected_active=None)
    trial.activate(child, expected_active=parent)
    rollback_id = trial.rollback(expected_child=child)
    restored = evaluate_artifact(store, case_id, witness_control["candidate_id"], parent, "proxy")
    report = {"schema_version": 1, "kind": "artifact_repair_validation", "case_id": case_id,
        "parent_revision": parent, "child_revision": child, "plan_id": selected["plan_id"],
        "provider_id": store.put_json({"kind": "artifact_docker_v1", "image": image}), "image": image,
        "baseline": baseline, "interventions": interventions, "witness_id": witness_id,
        "search_id": selection_id, "graph_id": graph_id, "controls": controls, "probe_id": probe_id,
        "probe_bundle_id": probe_bundle, "probe_payload": probe_payload,
        "rollback_id": rollback_id, "restored_proxy": restored}
    report["gates"] = _check_artifact_validation(store, report)
    identity = store.put_json(report)
    verify_artifact_validation(store, identity)
    with (root / "validation.json").open("x") as ref:
        json.dump({"validation_id": identity}, ref)
    notify("VALIDATED", {"validation_id": identity, "all_gates_passed": all(report["gates"].values())})
    return identity


def _check_artifact_validation(store, report):
    case_id = report["case_id"]
    case, task = load_case(store, case_id)
    manager = _manager(store)
    parent_id, child_id = report["parent_revision"], report["child_revision"]
    parent, child = manager.load(parent_id), manager.load(child_id)
    plan = TypedRepairPlan.model_validate(store.get_json(report["plan_id"]))
    if (child.parent_identity != parent_id or child.image_identity != parent.image_identity
            or report["image"] != parent.image_identity
            or store.get_json(parent.task_identity) != task.model_dump(mode="json")
            or store.get_json(child.applied_plan_identity)["plan_identity"] != plan.identity
            or plan.parent_policy_identity != parent.policy.identity
            or report["provider_id"] != store.put_json({"kind": "artifact_docker_v1", "image": parent.image_identity})):
        raise IntegrityError("artifact plan, case and revisions are not one validation")
    execution_owners = {}

    def resolved(ref, candidate_id, revision_id, channel):
        result = resolve_artifact(store, ref, case_id=case_id, candidate_id=candidate_id,
                                  revision_id=revision_id, channel=channel)
        execution_id = result["inspection"]["Id"]
        if execution_id in execution_owners and execution_owners[execution_id] != ref:
            raise IntegrityError("one container was reused for different artifact evaluations")
        execution_owners[execution_id] = ref
        return result

    if len(report["baseline"]) != len(case["controls"]) or len(report["controls"]) != len(case["controls"]):
        raise IntegrityError("artifact corpus coverage is incomplete")
    baseline = []
    baseline_ok = True
    for row, control in zip(report["baseline"], case["controls"]):
        if row["name"] != control["name"] or row["candidate_id"] != control["candidate_id"]:
            raise IntegrityError("artifact baseline differs from the frozen split")
        proxy = resolved(row["proxy"], control["candidate_id"], parent_id, "proxy")
        audit = resolved(row["audit"], control["candidate_id"], parent_id, "audit")
        baseline.append((proxy, audit))
        baseline_ok &= audit["verdict"] == _expected(control)
        baseline_ok &= proxy["verdict"] == ("REJECT" if control["role"] == "negative" else "PASS")
    witness_files = load_files(store, report["witness_id"])
    original = load_files(store, case["controls"][4]["candidate_id"])
    if (witness_files.get("answer.json") != original.get("answer.json")
            or any(name not in original or data != original[name] for name, data in witness_files.items())):
        raise IntegrityError("minimization changed the semantic answer")
    graph = store.get_json(report["graph_id"])
    causal_files = sorted(set(witness_files) - {"answer.json"})
    if (graph["kind"] != "artifact_influence_graph" or graph["case_id"] != case_id
            or graph["interventions"] != report["interventions"] or graph["causal_files"] != causal_files):
        raise IntegrityError("artifact graph differs from the intervention evidence")
    intervention_results = []
    for row in report["interventions"]:
        files = load_files(store, row["candidate_id"])
        if files.get("answer.json") != original["answer.json"] or any(name not in original or data != original[name] for name, data in files.items()):
            raise IntegrityError("intervention changed bytes instead of removing files")
        result = resolved(row["proxy"], row["candidate_id"], parent_id, "proxy")
        intervention_results.append((files, result))
    causal = bool(causal_files)
    minimal = any(row["candidate_id"] == report["witness_id"] and result[1]["verdict"] == "PASS"
                  for row, result in zip(report["interventions"], intervention_results))
    for name in causal_files:
        causal &= any(a[1]["verdict"] == "PASS" and b[1]["verdict"] == "REJECT"
            and {key: data for key, data in a[0].items() if key != name} == b[0]
            for a in intervention_results for b in intervention_results)
        removed = {key: data for key, data in witness_files.items() if key != name}
        minimal &= any(files == removed and result["verdict"] == "REJECT" for files, result in intervention_results)
    selection = store.get_json(report["search_id"])
    if selection["case_id"] != case_id or len(selection["search"]) != 3:
        raise IntegrityError("artifact search is incomplete")
    expected_plans = _plans(parent.policy, causal_files)
    eligible = []
    unsafe_positive_rejected = False
    for row, expected_plan in zip(selection["search"], expected_plans):
        selected_plan = TypedRepairPlan.model_validate(store.get_json(row["plan_id"]))
        candidate_revision = manager.load(row["child_revision"])
        if (selected_plan != expected_plan or candidate_revision.parent_identity != parent_id
                or store.get_json(candidate_revision.applied_plan_identity)["plan_identity"] != selected_plan.identity
                or len(row["development"]) != 6):
            raise IntegrityError("search candidate differs from its evaluated typed overlay")
        outcomes = [resolved(ref, control["candidate_id"], row["child_revision"], "sealed")
                    for ref, control in zip(row["development"], case["controls"][:6])]
        preserved = all(result["verdict"] == _expected(control)
                        for result, control in zip(outcomes, case["controls"][:6]))
        if row["preserved"] is not preserved:
            raise IntegrityError("search preservation flag contradicts raw development outcomes")
        unsafe_positive_rejected |= outcomes[4]["verdict"] == "REJECT" and any(r["verdict"] != "PASS" for r in outcomes[:2])
        if preserved:
            eligible.append(row)
    if not eligible:
        raise IntegrityError("artifact validation has no eligible selected plan")
    expected_selection = min(eligible, key=lambda row: (
        len(manager.load(row["child_revision"]).policy.candidate_files),
        len(store.get_json(row["plan_id"])["steps"]), row["plan_id"]))
    if (selection["child_revision"] != child_id or selection["plan_id"] != report["plan_id"]
            or expected_selection["child_revision"] != child_id or expected_selection["plan_id"] != report["plan_id"]):
        raise IntegrityError("selected artifact plan is not the frozen development-only winner")
    positives = negatives = heldout = parity = repeats = privilege = True
    for row, control, before in zip(report["controls"], case["controls"], baseline):
        if row["name"] != control["name"] or row["candidate_id"] != control["candidate_id"] or len(row["sealed"]) != 3:
            raise IntegrityError("sealed matrix changed the frozen controls or repeat count")
        results = [resolved(ref, control["candidate_id"], child_id, "sealed") for ref in row["sealed"]]
        if len({r["inspection"]["Id"] for r in results}) != 3:
            raise IntegrityError("sealed clean repeats reuse a container")
        expected = _expected(control)
        passed = all(r["verdict"] == expected and (expected == "PASS" or r["counts"]["failed"] > 0) for r in results)
        if control["role"] == "positive": positives &= passed
        elif control["role"] == "heldout": heldout &= passed
        else: negatives &= passed
        if control["role"] in {"positive", "negative"}:
            parity &= all(r["verdict"] == before[0]["verdict"] for r in results)
        repeats &= len({canonical_json({key: r[key] for key in ("verdict", "counts")}) for r in results}) == 1
        parent_files = load_files(store, before[0]["bundle_id"])
        for result in results:
            child_files = load_files(store, result["bundle_id"])
            privilege &= all(name in parent_files and parent_files[name] == data for name, data in child_files.items())
            privilege &= result["inspection"]["Config"].get("Env") == before[0]["inspection"]["Config"].get("Env")
    probe = verify_bundle_execution(store, report["probe_id"], bundle_id=report["probe_bundle_id"],
        image=report["image"], worker=PROBE_CODE, payload=report["probe_payload"])
    expected_probe_bundle, _, _ = _inputs(store, case, task, case["controls"][2]["candidate_id"], child.policy, "sealed")
    if report["probe_bundle_id"] != expected_probe_bundle or probe["inspection"]["Id"] in execution_owners:
        raise IntegrityError("capability probe differs from the selected input policy")
    probe_result = interpret_probe(probe["process"], report["probe_payload"]["nonce"],
        projected_entries=tuple(sorted(load_files(store, expected_probe_bundle))))
    rollback = RevisionTransition.model_validate(store.get_json(report["rollback_id"]))
    restored = resolved(report["restored_proxy"], case["controls"][4]["candidate_id"], parent_id, "proxy")
    return {"confirmed_false_reward": baseline[4][0]["verdict"] == "PASS" and baseline[4][1]["verdict"] == "REJECT",
        "baseline_oracle": bool(baseline_ok), "causal_witness": bool(causal), "one_file_minimal_witness": bool(minimal),
        "unsafe_positive_rejected": bool(unsafe_positive_rejected), "positives_preserved": bool(positives),
        "ordinary_and_exploit_rejection": bool(negatives), "committed_heldouts": bool(heldout),
        "native_parity": bool(parity), "three_clean_repeats": bool(repeats),
        "measured_privilege_monotonicity": bool(privilege),
        "declared_privilege_monotonicity": child.policy.privileges.no_broader_than(parent.policy.privileges),
        "active_provider_enforcement": probe_result["passed"],
        "owned_bound_verdict": child.policy.verdict_owner == "trusted_verifier" and child.policy.result_bindings == REQUIRED_BINDINGS,
        "managed_rollback": rollback.action == "rollback" and rollback.before == child_id and rollback.after == parent_id
            and rollback.restored_artifacts == parent.artifacts and rollback.cache_namespace == manager.cache_namespace(parent_id)
            and restored["verdict"] == "PASS"}


def verify_artifact_validation(store: ContentAddressedStore, identity: str) -> dict:
    return _verify_artifact_validation(VerificationSnapshot(store), identity)


def _verify_artifact_validation(store: ContentAddressedStore, identity: str) -> dict:
    report = store.get_json(identity)
    if report["kind"] != "artifact_repair_validation" or report["schema_version"] != 1:
        raise IntegrityError("unsupported artifact validation report")
    checked = _check_artifact_validation(store, report)
    if report["gates"] != checked or any(type(v) is not bool for v in report["gates"].values()):
        raise IntegrityError("artifact validation gates contradict raw evidence")
    return report


def promote_artifact(root: Path, validation_id: str) -> dict:
    store = ContentAddressedStore(root / "evidence")
    report = verify_artifact_validation(store, validation_id)
    if not all(report["gates"].values()):
        raise IntegrityError("failed artifact obligations prohibit promotion")
    seal = SealEvidence(adapter="artifact_output_v1", parent_revision=report["parent_revision"],
        child_revision=report["child_revision"], case_identity=report["case_id"], dataset_revision=report["case_id"],
        plan_identity=report["plan_id"], validation_identity=validation_id, provider_identity=report["provider_id"],
        image_identity=report["image"],
        verify_command=("autoseal", "artifact-repair", "verify", validation_id, "--root", "ROOT"),
        rollback_command=("autoseal", "artifact-repair", "rollback", "--root", "ROOT", "--expected-child", report["child_revision"]),
        assumptions=("Trusted manager and CAS", "Authored seeded fixed-output task", "Scoped Mac Docker research deployment"),
        expiration_conditions=("Any bound task, code, policy, image, provider or corpus change requires revalidation",))
    seal_id = store.put_json(seal.model_dump(mode="json"))
    manager = deployment_manager(root)
    if manager.active() == report["child_revision"]:
        pointer = json.loads((manager.root / "active.json").read_bytes())
        transition = store.get_json(pointer["transition"])
        if transition.get("admission_identity") != seal_id:
            raise IntegrityError("active child was promoted through different evidence")
        activation = pointer["transition"]
    else:
        activation = manager.activate(report["child_revision"], expected_active=report["parent_revision"], admission_identity=seal_id)
    return {"disposition": "PROMOTED", "seal_evidence_id": seal_id, "activation_id": activation,
            "validation_id": validation_id, "child_revision": report["child_revision"]}


def rollback_artifact(root: Path, expected_child: str) -> str:
    return deployment_manager(root).rollback(expected_child=expected_child)
