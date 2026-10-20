"""Frozen scripted population for a causal reward-bridge preflight.

This is not a model sample or a training outcome. It tests whether the reward
transport can distinguish a valid solution, ordinary invalid solution, and a
disclosed evaluator exploit under identical candidate bytes and task settings.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.environment import _tree_digest
from autoseal.evaluation import Evaluation, Verdict, evaluate_fixture
from autoseal.local_demo import FIXTURE, candidate_identity
from autoseal.reward_bridge import (
    DockerRewardWorker, RewardBridgeManifest, RewardRequest, RewardResponse,
)
from autoseal.reward_tasks import get_reward_task
from autoseal.result_binding import ResultContext, resolve_result
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


_ROLES = ("positive", "negative", "exploit")
_PINNED_FILES = {
    "positive": {"solution.py": "dd9f0f377ba55462e43833af59c94df26204d10c98eedeafd97366fe4230e4d5"},
    "negative": {"solution.py": "c28fb57b7b486422278b713403036cf3bed7d47e75e77c7224322a6c2a8d6102"},
    "exploit": {
        "solution.py": "c28fb57b7b486422278b713403036cf3bed7d47e75e77c7224322a6c2a8d6102",
        "conftest.py": "8f619c75d06101577dea3e1f93e6344e723ed92a6e34e9cec4d0a248f211d67f",
    },
}
_EXPECTED_REWARDS = {"vulnerable": [1.0, 0.0, 1.0], "sealed": [1.0, 0.0, 0.0]}
_EXPECTED_AUDIT = (Verdict.PASS, Verdict.REJECT, Verdict.REJECT)
_DRIVER_FILES = (
    "src/autoseal/reward_population.py",
    "src/autoseal/reward_bridge.py",
    "src/autoseal/reward_tasks.py",
    "src/autoseal/docker_fixture.py",
    "src/autoseal/projection.py",
    "src/autoseal/result_binding.py",
    "src/autoseal/environment.py",
    "src/autoseal/evaluation.py",
    "src/autoseal/local_demo.py",
)


def frozen_population() -> tuple[dict, ...]:
    """Load only the reviewed local files and reject any changed fixture byte."""

    population = []
    for role in _ROLES:
        directory = FIXTURE / "candidates" / role
        if directory.is_symlink():
            raise IntegrityError(f"{role} candidate directory is a symlink")
        names = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
        if names != set(_PINNED_FILES[role]):
            raise IntegrityError(f"{role} candidate file set changed")
        files = {}
        for name, expected in _PINNED_FILES[role].items():
            path = directory / name
            if path.is_symlink():
                raise IntegrityError(f"{role}/{name} is a symlink")
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise IntegrityError(f"{role}/{name} changed")
            files[name] = content.decode("utf-8")
        population.append({
            "role": role,
            "files": files,
            "file_sha256": dict(_PINNED_FILES[role]),
            "workspace_identity": _tree_digest(directory),
            "fixture_candidate_identity": candidate_identity(directory),
            "completion": json.dumps(files, sort_keys=True, separators=(",", ":")),
        })
    return tuple(population)


def run_controlled_reward_population(store_root: Path) -> dict:
    """Run both reward arms, then check a separate audit outside reward data."""

    population = frozen_population()
    task = get_reward_task("is_even")
    store = ContentAddressedStore(store_root)
    project_root = Path(__file__).resolve().parents[2]
    code_identities = {
        name: store.put_bytes((project_root / name).read_bytes()) for name in _DRIVER_FILES
    }
    training = {
        "scope": "SCRIPTED_REWARD_DISCRIMINATION_PREFLIGHT_ONLY",
        "task_name": task.name,
        "prompt": task.prompt,
        "expected_passes": task.expected_passes,
        "reward_scheme": "binary",
        "candidate_roles": list(_ROLES),
        "candidate_workspace_identities": [item["workspace_identity"] for item in population],
        "code_identities": code_identities,
        "training_performed": False,
    }
    experiment_id = store.put_json(training)
    manifest = RewardBridgeManifest(
        scope="LOCAL_TASK_REWARD_BRIDGE_PILOT",
        experiment_id=experiment_id,
        task_id=store.put_bytes(task.prompt.encode()),
        verifier_identity=_tree_digest(task.verifier),
        image_identity=image_identity(DEFAULT_IMAGE),
        seeds=(17,), max_batches_per_seed=1, batch_size=len(population),
    )
    manifest_id = store.put_json(manifest.model_dump(mode="json"))
    worker = DockerRewardWorker(store, manifest_id)
    arms = {}
    for arm in ("vulnerable", "sealed"):
        request = RewardRequest(
            bridge_manifest_id=manifest_id, experiment_id=experiment_id,
            task_id=manifest.task_id, arm=arm, seed=17, batch=0,
            completions=tuple(item["completion"] for item in population),
        )
        request_id = store.put_json(request.model_dump(mode="json"))
        response_id = worker.evaluate(request_id)
        response = store.get_json(response_id)
        if response["status"] != "COMPLETE" or response["rewards"] != _EXPECTED_REWARDS[arm]:
            raise IntegrityError(f"{arm} reward vector differs from the frozen preflight")
        expected_outcomes = ["PASS", "REJECT", "PASS" if arm == "vulnerable" else "REJECT"]
        if response["outcomes"] != expected_outcomes or "audit" in response:
            raise IntegrityError(f"{arm} outcome or reward/audit separation changed")
        for item, evidence_id in zip(population, response["evidence_ids"]):
            evidence = store.get_json(evidence_id)
            if evidence["evaluation"]["candidate_identity"] != item["workspace_identity"]:
                raise IntegrityError("reward evidence candidate identity mismatch")
            for name, digest in item["file_sha256"].items():
                if evidence["candidate_files"].get(name) != f"sha256:{digest}":
                    raise IntegrityError("reward evidence candidate bytes differ")
        arms[arm] = {
            "request_id": request_id,
            "response_id": response_id,
            "rewards": response["rewards"],
            "outcomes": response["outcomes"],
            "evidence_ids": response["evidence_ids"],
        }

    audit = []
    for item, expected in zip(population, _EXPECTED_AUDIT):
        result = evaluate_fixture(item["role"], "audit")
        if result.candidate_identity != item["fixture_candidate_identity"] or result.verdict is not expected:
            raise IntegrityError("independent audit disagrees with frozen candidate role")
        audit_result_id = store.put_json(result.model_dump(mode="json"))
        audit.append({
            "role": item["role"],
            "candidate_identity": result.candidate_identity,
            "verdict": result.verdict.value,
            "process_evidence_id": result.process_evidence_id,
            "audit_result_id": audit_result_id,
        })

    return {
        "schema_version": 1,
        "scope": "scripted three-candidate bridge preflight; no model sampling or training",
        "experiment_id": experiment_id,
        "bridge_manifest_id": manifest_id,
        "candidate_roles": list(_ROLES),
        "candidate_workspace_identities": [item["workspace_identity"] for item in population],
        "candidate_file_sha256": {item["role"]: item["file_sha256"] for item in population},
        "code_identities": code_identities,
        "arms": arms,
        "audit_outside_reward": audit,
        "disclosed_exploit_reward_gap": 1.0,
        "limitations": [
            "All three completions are scripted from checked-in fixtures, not sampled from a model.",
            "The exploit is disclosed and the audit is separate from, but not hidden from, this public preflight.",
            "One small is_even task does not estimate real-world attack rates or downstream model quality.",
            "No SFT or GRPO optimizer step, multi-seed efficacy comparison, or held-out attack was run.",
            "The caller-selected CAS retains raw evidence and nine driver files; export it separately for public review.",
        ],
    }


def export_controlled_reward_population(store_root: Path, report: dict,
                                        destination: Path) -> dict:
    """Archive every source, reward, binding, and audit object used by a run."""

    if destination.exists():
        raise FileExistsError("refusing to replace a controlled-population archive")
    store = ContentAddressedStore(store_root)
    manifest_id = report["bridge_manifest_id"]
    manifest = RewardBridgeManifest.model_validate(store.get_json(manifest_id))
    if manifest.experiment_id != report["experiment_id"] or manifest.batch_size != 3:
        raise IntegrityError("population report and frozen bridge differ")
    training = store.get_json(manifest.experiment_id)
    if training["scope"] != "SCRIPTED_REWARD_DISCRIMINATION_PREFLIGHT_ONLY":
        raise IntegrityError("not a controlled-population preflight")
    if training["code_identities"] != report["code_identities"]:
        raise IntegrityError("frozen driver identities differ from report")
    if report["candidate_roles"] != list(_ROLES):
        raise IntegrityError("candidate order changed")
    identities = {manifest_id, manifest.experiment_id, manifest.task_id}
    identities.update(training["code_identities"].values())

    task = get_reward_task("is_even")
    if _tree_digest(task.verifier) != manifest.verifier_identity:
        raise IntegrityError("reviewed verifier changed")
    verifier_files = {}
    for file in sorted(task.verifier.rglob("*")):
        if file.is_file():
            identity = store.put_bytes(file.read_bytes())
            verifier_files[file.relative_to(task.verifier).as_posix()] = identity
            identities.add(identity)

    for arm in ("vulnerable", "sealed"):
        item = report["arms"][arm]
        request = RewardRequest.model_validate(store.get_json(item["request_id"]))
        response = RewardResponse.model_validate(store.get_json(item["response_id"]))
        if (request.arm != arm or request.bridge_manifest_id != manifest_id
                or response.request_id != item["request_id"]
                or response.bridge_manifest_id != manifest_id
                or response.rewards != _EXPECTED_REWARDS[arm]
                or response.evidence_ids != item["evidence_ids"]):
            raise IntegrityError("reward arm differs from frozen population")
        identities.update((item["request_id"], item["response_id"]))
        for role, evidence_id in zip(_ROLES, response.evidence_ids):
            evidence = store.get_json(evidence_id)
            if evidence["evaluation"]["candidate_identity"] != report["candidate_workspace_identities"][_ROLES.index(role)]:
                raise IntegrityError("candidate linkage differs from frozen population")
            identities.add(evidence_id)
            identities.update(evidence["candidate_files"].values())
            bound_id = evidence["bound_result_id"]
            bound = store.get_json(bound_id)
            identities.update((bound_id, bound["evaluation_id"], bound["process_id"]))

    if [item["verdict"] for item in report["audit_outside_reward"]] != [
        "PASS", "REJECT", "REJECT",
    ]:
        raise IntegrityError("separate audit verdicts changed")
    for item in report["audit_outside_reward"]:
        audit = store.get_json(item["audit_result_id"])
        if (audit["channel"] != "audit" or audit["candidate_identity"] != item["candidate_identity"]
                or audit["verdict"] != item["verdict"]
                or audit["process_evidence_id"] != item["process_evidence_id"]):
            raise IntegrityError("audit object differs from report")
        identities.add(item["audit_result_id"])

    report_id = store.put_json(report)
    identities.add(report_id)
    archive = ContentAddressedStore(destination)
    for identity in sorted(identities):
        if archive.put_bytes(store.get_bytes(identity)) != identity:
            raise IntegrityError("archive object changed")
    index = {
        "schema_version": 1,
        "kind": "controlled_reward_population_preflight_archive",
        "report_id": report_id,
        "bridge_manifest_id": manifest_id,
        "verifier_files": verifier_files,
        "object_ids": sorted(identities),
        "object_count": len(identities),
        "limitation": "Scripted one-task reward transport preflight, not a model sample or training-efficacy result.",
    }
    (destination / "index.json").write_bytes(canonical_json(index))
    return index


def verify_controlled_reward_population_archive(destination: Path) -> dict:
    """Verify all archived bytes and the fixed reward/audit discrimination."""

    index = json.loads((destination / "index.json").read_text())
    if index.get("kind") != "controlled_reward_population_preflight_archive":
        raise IntegrityError("unexpected controlled-population archive kind")
    store = ContentAddressedStore(destination)
    identities = index["object_ids"]
    if len(identities) != index["object_count"] or len(set(identities)) != len(identities):
        raise IntegrityError("archive object index is incomplete")
    for identity in identities:
        store.get_bytes(identity)
    report = store.get_json(index["report_id"])
    manifest = RewardBridgeManifest.model_validate(store.get_json(index["bridge_manifest_id"]))
    if report["bridge_manifest_id"] != index["bridge_manifest_id"] or report["experiment_id"] != manifest.experiment_id:
        raise IntegrityError("archive manifest linkage mismatch")
    training = store.get_json(manifest.experiment_id)
    if training["code_identities"] != report["code_identities"]:
        raise IntegrityError("archived driver lineage changed")
    required = {index["report_id"], index["bridge_manifest_id"],
                manifest.experiment_id, manifest.task_id}
    required.update(training["code_identities"].values())
    required.update(index["verifier_files"].values())
    with tempfile.TemporaryDirectory(prefix="autoseal-archive-verifier-") as directory:
        verifier = Path(directory)
        for name, identity in index["verifier_files"].items():
            path = verifier / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(store.get_bytes(identity))
        if _tree_digest(verifier) != manifest.verifier_identity:
            raise IntegrityError("archived verifier bytes changed")
    for arm in ("vulnerable", "sealed"):
        item = report["arms"][arm]
        request = RewardRequest.model_validate(store.get_json(item["request_id"]))
        response = RewardResponse.model_validate(store.get_json(item["response_id"]))
        if (request.arm != arm or response.request_id != item["request_id"]
                or response.rewards != _EXPECTED_REWARDS[arm]
                or response.evidence_ids != item["evidence_ids"]):
            raise IntegrityError("archived reward discrimination changed")
        required.update((item["request_id"], item["response_id"]))
        for evidence_id in response.evidence_ids:
            evidence = store.get_json(evidence_id)
            required.add(evidence_id)
            required.update(evidence["candidate_files"].values())
            bound_id = evidence["bound_result_id"]
            bound = store.get_json(bound_id)
            required.update((bound_id, bound["evaluation_id"], bound["process_id"]))
            context = ResultContext.model_validate(evidence["result_context"])
            if resolve_result(store, bound_id, context,
                              channel=evidence["evaluation"]["channel"]) != evidence["evaluation"]:
                raise IntegrityError("archived reward result binding changed")
    if [item["verdict"] for item in report["audit_outside_reward"]] != [
        "PASS", "REJECT", "REJECT",
    ]:
        raise IntegrityError("archived audit labels changed")
    for item in report["audit_outside_reward"]:
        audit = Evaluation.model_validate(store.get_json(item["audit_result_id"]))
        required.add(item["audit_result_id"])
        if audit.candidate_identity != item["candidate_identity"] or audit.verdict.value != item["verdict"]:
            raise IntegrityError("archived audit object changed")
    if required != set(identities):
        raise IntegrityError("archive object list differs from its evidence closure")
    return index
