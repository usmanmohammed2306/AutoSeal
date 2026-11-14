"""Verify a finite SFT pause/resume archive and its paired development audit.

No optimizer is deserialized here. A successful format calibration never
satisfies the multi-seed vulnerable-versus-sealed training requirement.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import PurePosixPath

from autoseal.model_artifacts import verify_packet_evaluation
from autoseal.storage import IntegrityError, canonical_json
from autoseal.syntax_dataset import training_rows


def _require(condition, message):
    if not condition:
        raise IntegrityError(message)


def check_samples(requests, samples):
    _require(len(samples) == len(requests) > 0, "SFT validation denominator changed")
    ids = [request["id"] for request in requests]
    _require(len(ids) == len(set(ids)), "SFT validation request IDs repeat")
    for request, sample in zip(requests, samples):
        prompt_id = "sha256:" + hashlib.sha256(request["prompt"].encode()).hexdigest()
        _require(sample["request_id"] == request["id"] and sample["prompt_id"] == prompt_id
            and all(sample[key] == request[key] for key in ("case", "mode"))
            and isinstance(sample["completion"], str), "SFT validation sample linkage changed")


def _verify_files(store, expected, refs):
    _require(bool(expected) and set(expected) == set(refs), "SFT file inventory changed")
    _require(sum(item["bytes"] for item in expected.values()) <= 256 * 1024**2, "SFT archive exceeds the byte bound")
    for name, item in expected.items():
        path = PurePosixPath(name)
        _require(not path.is_absolute() and len(path.parts) == 1 and name not in {".", ".."}, "unsafe SFT file name")
        content = store.get_bytes(refs[name])
        _require(len(content) == item["bytes"] and refs[name] == "sha256:" + item["sha256"],
                 "SFT retained file differs from its checkpoint manifest")


def verify_sft_archive(store, identity):
    archive = store.get_json(identity)
    _require(archive["kind"] == "sft_pause_resume_archive" and archive["schema_version"] == 1,
             "unsupported SFT archive")
    config_id = archive["configuration_id"]
    config = store.get_json(config_id)
    _require(config["kind"] == "artifact_sft_training" and config["schema_version"] == 1
        and config["scope"] == "FORMAT_CALIBRATION", "SFT calibration scope changed")
    _require(config["training_examples"] == training_rows(store, config["dataset_revision"])
        and store.get_bytes(config["dataset_bytes_id"]) == canonical_json(config["training_examples"]),
        "SFT training rows differ from the reviewed train split")
    for digest in config["sources"].values():
        store.get_bytes(digest)
    base_id = store.put_json(config["model_files"])
    pause = store.get_json(archive["pause_evidence_id"])
    report = store.get_json(archive["report_id"])
    common = {"configuration_id": config_id, "dataset_revision": config["dataset_revision"],
        "dataset_bytes_id": config["dataset_bytes_id"], "base_identity": base_id, "seed": config["seed"],
        "scope": config["scope"], "kind": "artifact_sft_training_report", "schema_version": 1, "error": None}
    for observed in (pause["report"], report):
        _require(all(observed[key] == value for key, value in common.items()), "SFT report lineage changed")
    stop = config["pause_test"]["pause_at_step"]
    _require(type(stop) is int and 0 < stop < config["max_steps"] == config["pause_test"]["resume_to_step"],
        "invalid frozen SFT pause/resume budget")
    _require(pause["report"]["status"] == "PAUSED_AT_CHECKPOINT" and pause["report"]["global_step"] == stop
        and pause["report"]["resumed_from_step"] is None and report["status"] == "COMPLETE"
        and report["global_step"] == config["max_steps"] and report["resumed_from_step"] == stop,
        "SFT pause or resumed optimizer budget is incomplete")
    baseline = store.get_json(archive["baseline_id"])
    samples = store.get_json(archive["validation_id"])
    _require(pause["baseline"] == baseline and report["samples"] == samples,
        "SFT baseline or post-training validation was replaced")
    check_samples(config["validation_requests"], baseline)
    check_samples(config["validation_requests"], samples)
    for phase, observed in (("pause", pause["report"]), ("resume", report)):
        proof = observed["checkpoint_manifest"]
        _require(all(proof[key] == value for key, value in {"configuration_id": config_id,
            "dataset_id": config["dataset_revision"], "base_identity": base_id,
            "global_step": observed["global_step"]}.items()), "SFT checkpoint lineage changed")
        if phase == "pause":
            _require(proof == pause["proof"], "SFT pause proof differs from the saved report")
        refs = archive["checkpoint_files"][phase]
        _verify_files(store, proof["checkpoint_files"], refs)
        state = store.get_json(refs["trainer_state.json"])
        _require(state["global_step"] == observed["global_step"]
            and store.get_json(refs["autoseal-baseline.json"]) == baseline, "SFT checkpoint state changed")
    _verify_files(store, report["adapter_files"], archive["adapter_files"])
    _require(report["adapter_files"]["adapter_model.safetensors"]["sha256"] ==
        report["checkpoint_manifest"]["checkpoint_files"]["adapter_model.safetensors"]["sha256"],
        "SFT exported adapter differs from the resumed checkpoint")
    scheduler = store.get_bytes(archive["scheduler_id"]).decode()
    for observed in (pause["report"], report):
        job = str(observed["slurm_job_id"])
        matches = [line.split() for line in scheduler.splitlines() if line.split() and line.split()[0] == job]
        _require(len(matches) == 1 and matches[0][1] == "COMPLETED" and matches[0][-1] == "0:0",
            "SFT scheduler did not confirm successful job completion")
    return {"archive_id": identity, "configuration_id": config_id, "seed": config["seed"],
        "resumed_from_step": stop, "global_step": report["global_step"], "attempted_per_phase": len(samples),
        "adapter_id": archive["adapter_files"]["adapter_model.safetensors"],
        "scope": "Single-seed format calibration with known development prompts; no paired GRPO efficacy claim."}


def summarize(rows):
    return {"attempted": len(rows), "syntax_valid": sum(row["syntax_valid"] for row in rows),
        "audit_pass": sum(row["channels"].get("audit", {}).get("verdict") == "PASS" for row in rows),
        "proxy_pass": sum(row["channels"].get("proxy", {}).get("verdict") == "PASS" for row in rows),
        "classifications": dict(Counter(row["classification"] for row in rows)),
        "fixed_wrong_adherent": sum(row.get("fixed_wrong_adherent") is True for row in rows)}


def verify_sft_evaluation(store, identity):
    evaluation = store.get_json(identity)
    _require(evaluation["kind"] == "sft_development_evaluation" and evaluation["schema_version"] == 1,
        "unsupported SFT evaluation")
    checked = verify_sft_archive(store, evaluation["training_archive_id"])
    archive = store.get_json(evaluation["training_archive_id"])
    config = store.get_json(archive["configuration_id"])
    _require(set(evaluation["phases"]) == {"baseline", "post_sft"}, "SFT comparison is missing a phase")
    for phase, sample_id in (("baseline", archive["baseline_id"]), ("post_sft", archive["validation_id"])):
        rows = evaluation["phases"][phase]["rows"]
        samples = store.get_json(sample_id)
        _require(len(rows) == len(samples), "SFT evaluation dropped an attempted completion")
        for request, sample, row in zip(config["validation_requests"], samples, rows):
            verify_packet_evaluation(store, row, request=request, completion=sample["completion"], image=evaluation["image"])
        _require(evaluation["phases"][phase]["summary"] == summarize(rows), "SFT evaluation counts contradict receipts")
    return {**checked, "evaluation_id": identity,
        "phases": {phase: value["summary"] for phase, value in evaluation["phases"].items()},
        "limitations": evaluation["limitations"]}


def calibration_view(store, identity):
    """A verified, bounded product view, with no checkpoint download endpoint."""
    checked = verify_sft_evaluation(store, identity)
    evaluation = store.get_json(identity)
    archive = store.get_json(evaluation['training_archive_id'])
    config = store.get_json(archive['configuration_id'])
    report = store.get_json(archive['report_id'])
    # Trainer state is saved just before its final aggregate log entry. Match
    # the per-update records; the paused library aggregate is not a speed or
    # comparable training-loss metric.
    state = store.get_json(archive['checkpoint_files']['resume']['trainer_state.json'])
    curve = [row for row in report['log_history'] if 'loss' in row]
    saved = [row for row in state['log_history'] if 'loss' in row]
    _require(curve == saved and [row['step'] for row in curve] == list(range(1, report['global_step'] + 1)),
        'SFT per-update curve differs from checkpoint state')
    for row in curve:
        _require(all(isinstance(row[key], (int, float)) and not isinstance(row[key], bool)
            and math.isfinite(row[key]) and row[key] >= 0 for key in ('loss', 'grad_norm', 'learning_rate')),
            'invalid SFT per-update metric')
    return {**checked, 'model_source': config['model_source'], 'dataset_revision': config['dataset_revision'],
        'training_examples': len(config['training_examples']), 'loss_scope': config['loss_scope'],
        'max_steps': config['max_steps'], 'trainable_parameters': report['trainable_parameters'],
        'peak_gpu_bytes': report['peak_gpu_bytes'], 'gpu': report['gpu'],
        'curve': [{key: row[key] for key in ('step', 'loss', 'grad_norm', 'learning_rate')} for row in curve],
        'scheduler': store.get_bytes(archive['scheduler_id']).decode(),
        'report_id': archive['report_id']}
