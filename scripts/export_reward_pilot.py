"""Archive a verified GRPO reward-bridge pilot without publishing model weights.

The output includes frozen configuration, paired run reports, reward requests,
responses, evaluator evidence, and candidate source objects. Adapter digests
are recorded, but the adapter binaries stay in the private local artifact area.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3

from autoseal.storage import ContentAddressedStore, canonical_json
from autoseal.environment import _tree_digest
from autoseal.reward_tasks import get_reward_task
from scripts.analyze_reward_pilot import analyze


def export(store: ContentAddressedStore, output_root: Path, configuration_id: str, destination: Path) -> dict:
    if destination.exists():
        raise FileExistsError("refusing to replace an archived pilot")
    summary = analyze(store, output_root, configuration_id)
    config = store.get_json(configuration_id)
    manifest = config["bridge_manifest"]
    identities = {configuration_id, config["bridge_manifest_id"],
                  manifest["experiment_id"], manifest["task_id"]}
    source_missing = []
    root = Path(__file__).resolve().parents[1]
    for name, identity in config["training_configuration"]["code_identities"].items():
        try:
            store.get_bytes(identity)
        except FileNotFoundError:
            current = (root / name).read_bytes()
            if "sha256:" + hashlib.sha256(current).hexdigest() == identity:
                store.put_bytes(current)
            else:
                source_missing.append(name)
                continue
        identities.add(identity)
    verifier_files = {}
    task = get_reward_task(config["training_configuration"].get("task_name", "is_even"))
    if _tree_digest(task.verifier) == manifest["verifier_identity"]:
        for file in sorted(task.verifier.rglob("*")):
            if file.is_file():
                identity = store.put_bytes(file.read_bytes())
                verifier_files[file.relative_to(task.verifier).as_posix()] = identity
                identities.add(identity)
    reports = {}
    for seed in manifest["seeds"]:
        for arm in ("vulnerable", "sealed"):
            name = f"{arm}_{seed}"
            report = json.loads((output_root / name / "result.json").read_text())
            report_id = store.put_json(report)
            reports[name] = report_id
            identities.add(report_id)
            for pair in report["batch_receipts"]:
                identities.update((pair["request_id"], pair["response_id"]))
                request = store.get_json(pair["request_id"])
                response = store.get_json(pair["response_id"])
                if len(request["completions"]) != len(response["evidence_ids"]):
                    raise ValueError("reward request and response length differ")
                identities.update(response["evidence_ids"])
                for evidence_id in response["evidence_ids"]:
                    evidence = store.get_json(evidence_id)
                    if evidence.get("kind") == "invalid_candidate_output":
                        identities.add(evidence["completion_id"])
                    else:
                        identities.update(evidence["candidate_files"].values())
                        if "bound_result_id" in evidence:
                            bound_id = evidence["bound_result_id"]
                            bound = store.get_json(bound_id)
                            identities.update((bound_id, bound["evaluation_id"], bound["process_id"]))
    archived = ContentAddressedStore(destination)
    for identity in sorted(identities):
        copied = archived.put_bytes(store.get_bytes(identity))
        if copied != identity:
            raise ValueError("evidence identity changed during export")
    index = {"schema_version": 1, "kind": "reward_bridge_pilot_archive",
             "configuration_id": configuration_id, "reports": reports,
             "summary": summary, "objects": len(identities),
             "missing_frozen_source_files": source_missing,
             "verifier_files": verifier_files,
             "limitation": "A one-task pipeline pilot, not a hidden-audit or research-scale training result. Adapter binaries are not included."}
    (destination / "index.json").write_bytes(canonical_json(index))
    return index


def export_preflight(store: ContentAddressedStore, report_path: Path,
                     configuration_id: str, destination: Path) -> dict:
    """Preserve one complete or failed condition without pretending it is a paired study."""

    if destination.exists():
        raise FileExistsError("refusing to replace an archived preflight")
    config = store.get_json(configuration_id)
    manifest_id = config["bridge_manifest_id"]
    manifest = config["bridge_manifest"]
    report = json.loads(report_path.read_text())
    arm, seed = report["arm"], report["seed"]
    if (report["configuration_id"] != configuration_id or arm not in {"vulnerable", "sealed"}
            or seed not in manifest["seeds"] or report["status"] not in {"COMPLETE", "FAILED"}):
        raise ValueError("report does not belong to the frozen preflight")
    with sqlite3.connect(f"file:{store.root / 'reward-bridge-index.sqlite3'}?mode=ro", uri=True) as connection:
        rows = connection.execute("SELECT batch, request, response FROM batches WHERE manifest=? AND arm=? AND seed=? ORDER BY batch",
                                  (manifest_id, arm, seed)).fetchall()
    if not rows or any(response is None for _, _, response in rows):
        raise ValueError("preflight has no completed reward response")
    observed = [{"batch": batch, "request_id": request, "response_id": response}
                for batch, request, response in rows]
    if report["status"] == "COMPLETE" and (
            report["global_steps"] != manifest["max_batches_per_seed"]
            or report["batch_receipts"] != observed):
        raise ValueError("completed report and observed reward batches disagree")
    if report["status"] == "FAILED" and any(
            pair not in observed for pair in report["batch_receipts"]):
        raise ValueError("failed report cites an unobserved reward batch")
    if report["status"] == "FAILED" and not report.get("error"):
        raise ValueError("failed preflight lacks an error record")
    identities = {configuration_id, manifest_id, manifest["experiment_id"], manifest["task_id"]}
    report_id = store.put_json(report)
    identities.add(report_id)
    root = Path(__file__).resolve().parents[1]
    missing_source = []
    for name, identity in config["training_configuration"]["code_identities"].items():
        try:
            store.get_bytes(identity)
        except FileNotFoundError:
            current = (root / name).read_bytes()
            if "sha256:" + hashlib.sha256(current).hexdigest() != identity:
                missing_source.append(name)
                continue
            store.put_bytes(current)
        identities.add(identity)
    task = get_reward_task(config["training_configuration"]["task_name"])
    if _tree_digest(task.verifier) != manifest["verifier_identity"]:
        raise ValueError("reviewed verifier changed after preflight freeze")
    verifier_files = {}
    for file in sorted(task.verifier.rglob("*")):
        if file.is_file():
            identity = store.put_bytes(file.read_bytes())
            verifier_files[file.relative_to(task.verifier).as_posix()] = identity
            identities.add(identity)
    for pair in observed:
        identities.update((pair["request_id"], pair["response_id"]))
        request = store.get_json(pair["request_id"])
        response = store.get_json(pair["response_id"])
        if (request["batch"] != pair["batch"] or request["arm"] != arm or request["seed"] != seed
                or response["request_id"] != pair["request_id"] or response["bridge_manifest_id"] != manifest_id
                or len(request["completions"]) != len(response["evidence_ids"])):
            raise ValueError("preflight reward pair does not match the frozen condition")
        for evidence_id in response["evidence_ids"]:
            identities.add(evidence_id)
            evidence = store.get_json(evidence_id)
            if evidence.get("kind") == "invalid_candidate_output":
                identities.add(evidence["completion_id"])
            else:
                identities.update(evidence["candidate_files"].values())
                bound_id = evidence["bound_result_id"]
                bound = store.get_json(bound_id)
                identities.update((bound_id, bound["evaluation_id"], bound["process_id"]))
    adapter = report_path.parent / "adapter" / "adapter_model.safetensors"
    adapter_identity = "sha256:" + hashlib.sha256(adapter.read_bytes()).hexdigest() if adapter.exists() else None
    archive = ContentAddressedStore(destination)
    for identity in sorted(identities):
        if archive.put_bytes(store.get_bytes(identity)) != identity:
            raise ValueError("preflight object changed during export")
    index = {"schema_version": 1, "kind": "reward_bridge_preflight_archive",
             "configuration_id": configuration_id, "report_id": report_id,
             "arm": arm, "seed": seed, "observed": observed,
             "verifier_files": verifier_files, "missing_frozen_source_files": missing_source,
             "adapter_identity": adapter_identity, "objects": len(identities),
             "limitation": "Single-condition preflight only. No paired comparison, held-out audit, or downstream improvement claim."}
    (destination / "index.json").write_bytes(canonical_json(index))
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument("--output-root", type=Path,
                        help="Directory of paired reports; not needed with --preflight-report")
    parser.add_argument("--configuration-id", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--preflight-report", type=Path,
                        help="Archive one complete or failed condition instead of a paired pilot")
    args = parser.parse_args()
    if args.preflight_report is None and args.output_root is None:
        parser.error("--output-root is required for a paired pilot")
    store = ContentAddressedStore(args.store)
    result = (export_preflight(store, args.preflight_report, args.configuration_id, args.destination)
              if args.preflight_report else
              export(store, args.output_root, args.configuration_id, args.destination))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
