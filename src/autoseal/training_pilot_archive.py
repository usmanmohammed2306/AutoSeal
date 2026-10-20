"""Offline integrity check for published, bounded training pilot evidence."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from autoseal.reward_bridge import RewardBridgeManifest, RewardRequest, RewardResponse
from autoseal.result_binding import ResultContext, resolve_result
from autoseal.reward_tasks import get_reward_task
from autoseal.storage import ContentAddressedStore, IntegrityError


def _validate_reward_evidence(outcome: str, reward: float | None,
                              evidence: dict, scheme: str, expected_passes: int) -> None:
    if outcome == "INVALID_OUTPUT":
        if evidence.get("kind") != "invalid_candidate_output" or reward != 0.0:
            raise IntegrityError("invalid candidate reward differs from its evidence")
        return
    evaluation = evidence.get("evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("verdict") != outcome:
        raise IntegrityError("reward outcome differs from raw evaluation")
    if outcome == "PASS":
        expected = 1.0
    elif outcome == "REJECT":
        expected = (min(evaluation["counts"]["passed"], expected_passes - 1) / expected_passes
                    if scheme == "pytest_pass_fraction_v1" else 0.0)
    else:
        expected = None
    if reward != expected:
        raise IntegrityError("reward differs from frozen scheme and raw test counts")


def load_training_pilot_archive(root: Path) -> dict:
    index = json.loads((root / "index.json").read_text())
    if index.get("schema_version") != 1 or index.get("kind") != "reward_bridge_pilot_archive":
        raise IntegrityError("unsupported training pilot archive")
    store = ContentAddressedStore(root)
    config = store.get_json(index["configuration_id"])
    manifest_id = config["bridge_manifest_id"]
    manifest = RewardBridgeManifest.model_validate(store.get_json(manifest_id))
    if manifest.model_dump(mode="json") != config["bridge_manifest"]:
        raise IntegrityError("training pilot manifest identity mismatch")
    store.get_json(manifest.experiment_id)
    store.get_bytes(manifest.task_id)
    training = config["training_configuration"]
    scheme = training.get("reward_scheme", "binary")
    if scheme not in {"binary", "pytest_pass_fraction_v1"}:
        raise IntegrityError("unknown archived reward scheme")
    expected_passes = training.get("expected_passes")
    if expected_passes is None:
        expected_passes = get_reward_task(training.get("task_name", "is_even")).expected_passes
    if not isinstance(expected_passes, int) or expected_passes <= 0:
        raise IntegrityError("invalid frozen expected test count")
    if manifest.scope == "LOCAL_TASK_REWARD_BRIDGE_PILOT" and not index.get("verifier_files"):
        raise IntegrityError("reviewed task archive lacks the frozen verifier files")
    if "verifier_files" in index and index["verifier_files"]:
        digest = hashlib.sha256(b"autoseal.workspace.v1\0")
        for relative, identity in sorted(index["verifier_files"].items()):
            name = relative.encode()
            content = store.get_bytes(identity)
            digest.update(len(name).to_bytes(8, "big"))
            digest.update(name)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        if "sha256:" + digest.hexdigest() != manifest.verifier_identity:
            raise IntegrityError("archived verifier files disagree with frozen tree identity")
    expected = {f"{arm}_{seed}" for seed in manifest.seeds for arm in ("vulnerable", "sealed")}
    if set(index["reports"]) != expected:
        raise IntegrityError("training pilot report matrix is incomplete")
    summary = index["summary"]
    if summary["configuration_id"] != index["configuration_id"] or not summary["paired_conditions_complete"]:
        raise IntegrityError("training pilot summary identity mismatch")
    summary_rows = {(item["arm"], item["seed"]): item for item in summary["conditions"]}
    if set(summary_rows) != {(arm, seed) for seed in manifest.seeds for arm in ("vulnerable", "sealed")}:
        raise IntegrityError("training pilot summary matrix is incomplete")
    for name, report_id in index["reports"].items():
        report = store.get_json(report_id)
        arm, seed_text = name.rsplit("_", 1)
        seed = int(seed_text)
        if (report["arm"] != arm or report["seed"] != seed or
            report["configuration_id"] != index["configuration_id"] or
            report["status"] != "COMPLETE" or report["global_steps"] != manifest.max_batches_per_seed or
            len(report["batch_receipts"]) != manifest.max_batches_per_seed):
            raise IntegrityError("training pilot report differs from frozen condition")
        outcomes, rewards = [], []
        for batch, pair in enumerate(report["batch_receipts"]):
            request = RewardRequest.model_validate(store.get_json(pair["request_id"]))
            response = RewardResponse.model_validate(store.get_json(pair["response_id"]))
            if (pair["batch"] != batch or request.batch != batch or request.arm != arm or
                request.seed != seed or request.bridge_manifest_id != manifest_id or
                request.experiment_id != manifest.experiment_id or request.task_id != manifest.task_id or
                response.request_id != pair["request_id"] or response.bridge_manifest_id != manifest_id or
                response.status != "COMPLETE"):
                raise IntegrityError("training pilot reward request/response mismatch")
            outcomes.extend(response.outcomes)
            rewards.extend(response.rewards)
            for outcome, reward, evidence_id in zip(response.outcomes, response.rewards, response.evidence_ids):
                evidence = store.get_json(evidence_id)
                _validate_reward_evidence(outcome, reward, evidence, scheme, expected_passes)
                if evidence.get("kind") == "invalid_candidate_output":
                    store.get_bytes(evidence["completion_id"])
                else:
                    for source_id in evidence["candidate_files"].values():
                        store.get_bytes(source_id)
                    if manifest.scope == "LOCAL_TASK_REWARD_BRIDGE_PILOT":
                        context = ResultContext.model_validate(evidence["result_context"])
                        resolved = resolve_result(store, evidence["bound_result_id"], context,
                                                  channel=evidence["evaluation"]["channel"])
                        if resolved != evidence["evaluation"]:
                            raise IntegrityError("bound reward result differs from archived evaluation")
        observed = summary_rows[(arm, seed)]
        if (observed["outcomes"] != dict(sorted(Counter(outcomes).items())) or
            observed["reward_sum"] != sum(rewards) or observed["samples"] != len(rewards)):
            raise IntegrityError("training pilot summary disagrees with raw reward receipts")
    return index


def load_training_preflight_archive(root: Path) -> dict:
    """Check a single-condition attempt without upgrading it to paired evidence."""

    index = json.loads((root / "index.json").read_text())
    if index.get("schema_version") != 1 or index.get("kind") != "reward_bridge_preflight_archive":
        raise IntegrityError("unsupported training preflight archive")
    store = ContentAddressedStore(root)
    config = store.get_json(index["configuration_id"])
    manifest_id = config["bridge_manifest_id"]
    manifest = RewardBridgeManifest.model_validate(store.get_json(manifest_id))
    if config["bridge_manifest"] != manifest.model_dump(mode="json"):
        raise IntegrityError("preflight manifest differs from frozen configuration")
    store.get_json(manifest.experiment_id)
    store.get_bytes(manifest.task_id)
    training = config["training_configuration"]
    scheme = training.get("reward_scheme", "binary")
    if scheme not in {"binary", "pytest_pass_fraction_v1"}:
        raise IntegrityError("unknown archived reward scheme")
    expected_passes = training.get("expected_passes")
    if expected_passes is None:
        expected_passes = get_reward_task(training.get("task_name", "is_even")).expected_passes
    if not isinstance(expected_passes, int) or expected_passes <= 0:
        raise IntegrityError("invalid frozen expected test count")
    for name, identity in config["training_configuration"]["code_identities"].items():
        if name not in index["missing_frozen_source_files"]:
            store.get_bytes(identity)
    if set(index["missing_frozen_source_files"]) - set(config["training_configuration"]["code_identities"]):
        raise IntegrityError("unknown missing source listed in preflight")
    digest = hashlib.sha256(b"autoseal.workspace.v1\0")
    if not index["verifier_files"]:
        raise IntegrityError("preflight verifier files are missing")
    for relative, identity in sorted(index["verifier_files"].items()):
        name = relative.encode()
        content = store.get_bytes(identity)
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    if "sha256:" + digest.hexdigest() != manifest.verifier_identity:
        raise IntegrityError("preflight verifier differs from frozen tree")
    report = store.get_json(index["report_id"])
    arm, seed = index["arm"], index["seed"]
    if (arm not in {"vulnerable", "sealed"} or seed not in manifest.seeds
            or report["configuration_id"] != index["configuration_id"]
            or report["arm"] != arm or report["seed"] != seed
            or report["status"] not in {"COMPLETE", "FAILED"}):
        raise IntegrityError("preflight report differs from frozen condition")
    observed = index["observed"]
    if (not observed or len(observed) > manifest.max_batches_per_seed or
            [pair["batch"] for pair in observed] != list(range(len(observed)))):
        raise IntegrityError("preflight reward batches are missing or unordered")
    if report["status"] == "COMPLETE" and (
            report["global_steps"] != manifest.max_batches_per_seed or
            len(observed) != manifest.max_batches_per_seed or
            report["batch_receipts"] != observed):
        raise IntegrityError("completed preflight lacks its full reward sequence")
    if report["status"] == "FAILED" and any(
            pair not in observed for pair in report["batch_receipts"]):
        raise IntegrityError("failed preflight cites an unobserved reward")
    if report["status"] == "FAILED" and not report.get("error"):
        raise IntegrityError("failed preflight lacks an error record")
    for pair in observed:
        request = RewardRequest.model_validate(store.get_json(pair["request_id"]))
        response = RewardResponse.model_validate(store.get_json(pair["response_id"]))
        if (request.batch != pair["batch"] or request.arm != arm or request.seed != seed or
                request.bridge_manifest_id != manifest_id or request.experiment_id != manifest.experiment_id or
                request.task_id != manifest.task_id or len(request.completions) != manifest.batch_size or
                response.request_id != pair["request_id"] or response.bridge_manifest_id != manifest_id or
                len(response.evidence_ids) != len(request.completions) or
                (report["status"] == "COMPLETE" and response.status != "COMPLETE")):
            raise IntegrityError("preflight reward is not bound to its request")
        for outcome, reward, evidence_id in zip(response.outcomes, response.rewards, response.evidence_ids):
            evidence = store.get_json(evidence_id)
            _validate_reward_evidence(outcome, reward, evidence, scheme, expected_passes)
            if evidence.get("kind") == "invalid_candidate_output":
                store.get_bytes(evidence["completion_id"])
            else:
                for source_id in evidence["candidate_files"].values():
                    store.get_bytes(source_id)
                context = ResultContext.model_validate(evidence["result_context"])
                resolved = resolve_result(store, evidence["bound_result_id"], context,
                                          channel=evidence["evaluation"]["channel"])
                if resolved != evidence["evaluation"]:
                    raise IntegrityError("preflight bound result differs from evaluation")
    return index
