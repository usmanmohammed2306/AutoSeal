"""Tamper checks use inert miniature files, never a claimed GPU result."""

import hashlib

import pytest

from autoseal.sft_archive import check_samples, verify_sft_archive, verify_sft_evaluation
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json
from autoseal.syntax_dataset import build_syntax_dataset, training_rows


def retained_run(tmp_path):
    store = ContentAddressedStore(tmp_path / 'evidence')
    dataset, _ = build_syntax_dataset(store)
    examples = training_rows(store, dataset)
    requests = [{'id': 'unit-only-request', 'prompt': 'unit-only prompt', 'case': 'skip-sum', 'mode': 'benign'}]
    samples = [{'request_id': requests[0]['id'], 'prompt_id': store.put_bytes(b'unit-only prompt'),
        'case': 'skip-sum', 'mode': 'benign', 'completion': '```json\n{}\n```'}]
    model_files = {'adapter_model.safetensors': {'bytes': 4, 'sha256': '0' * 64}}
    config = {'kind': 'artifact_sft_training', 'schema_version': 1, 'scope': 'FORMAT_CALIBRATION',
        'dataset_revision': dataset, 'training_examples': examples, 'dataset_bytes_id': store.put_json(examples),
        'model_files': model_files, 'seed': 17, 'sources': {'unit-only-driver.py': store.put_bytes(b'not executable')},
        'max_steps': 16, 'pause_test': {'pause_at_step': 8, 'resume_to_step': 16}, 'validation_requests': requests}
    config_id = store.put_json(config)
    base_id = store.put_json(model_files)
    common = {'kind': 'artifact_sft_training_report', 'schema_version': 1, 'configuration_id': config_id,
        'dataset_revision': dataset, 'dataset_bytes_id': config['dataset_bytes_id'], 'base_identity': base_id,
        'seed': 17, 'scope': 'FORMAT_CALIBRATION', 'error': None}
    def checkpoint(step):
        refs = {'trainer_state.json': store.put_json({'global_step': step}),
            'autoseal-baseline.json': store.put_json(samples),
            'adapter_model.safetensors': store.put_bytes(b'unit-only inert adapter'),
            'optimizer.pt': store.put_bytes(b'unit-only inert optimizer, never deserialized')}
        manifest = {name: {'bytes': len(store.get_bytes(ref)), 'sha256': ref[7:]} for name, ref in refs.items()}
        proof = {'configuration_id': config_id, 'dataset_id': dataset, 'base_identity': base_id,
            'global_step': step, 'checkpoint_files': manifest}
        return refs, proof
    pause_refs, pause_proof = checkpoint(8)
    final_refs, final_proof = checkpoint(16)
    pause_report = {**common, 'status': 'PAUSED_AT_CHECKPOINT', 'global_step': 8, 'resumed_from_step': None,
        'slurm_job_id': '1', 'checkpoint_manifest': pause_proof}
    report = {**common, 'status': 'COMPLETE', 'global_step': 16, 'resumed_from_step': 8,
        'slurm_job_id': '2', 'checkpoint_manifest': final_proof, 'samples': samples,
        'adapter_files': {'adapter_model.safetensors': final_proof['checkpoint_files']['adapter_model.safetensors']}}
    archive = {'kind': 'sft_pause_resume_archive', 'schema_version': 1, 'configuration_id': config_id,
        'pause_evidence_id': store.put_json({'report': pause_report, 'proof': pause_proof, 'baseline': samples}),
        'report_id': store.put_json(report), 'baseline_id': store.put_json(samples), 'validation_id': store.put_json(samples),
        'checkpoint_files': {'pause': pause_refs, 'resume': final_refs},
        'adapter_files': {'adapter_model.safetensors': final_refs['adapter_model.safetensors']},
        'scheduler_id': store.put_bytes(b'1 COMPLETED 00:01:00 0:0\n2 COMPLETED 00:01:00 0:0\n')}
    return store, archive


def test_checkpoint_archive_checks_bytes_without_deserializing(tmp_path):
    store, archive = retained_run(tmp_path)
    checked = verify_sft_archive(store, store.put_json(archive))
    assert checked['global_step'] == 16 and checked['resumed_from_step'] == 8
    assert 'Single-seed' in checked['scope']
    ref = archive['checkpoint_files']['resume']['optimizer.pt']
    store._path(ref).write_bytes(b'tampered optimizer')
    with pytest.raises(IntegrityError, match='digest mismatch'):
        verify_sft_archive(store, store.put_json(archive))


@pytest.mark.parametrize('change', ['seed', 'dataset', 'resume', 'scheduler', 'adapter', 'sample'])
def test_cannot_relabel_training_lineage_or_drop_failed_samples(tmp_path, change):
    store, archive = retained_run(tmp_path)
    report = store.get_json(archive['report_id'])
    if change == 'seed':
        report['seed'] = 22
    elif change == 'dataset':
        report['dataset_revision'] = store.put_json({'unreviewed': True})
    elif change == 'resume':
        report['resumed_from_step'] = None
    elif change == 'scheduler':
        archive['scheduler_id'] = store.put_bytes(b'1 COMPLETED 00:01:00 0:0\n2 TIMEOUT 00:10:00 0:15\n')
    elif change == 'adapter':
        archive['adapter_files']['adapter_model.safetensors'] = store.put_bytes(b'replaced')
    else:
        archive['validation_id'] = store.put_json([])
    archive['report_id'] = store.put_json(report)
    with pytest.raises(IntegrityError):
        verify_sft_archive(store, store.put_json(archive))


def test_evaluation_recounts_invalid_attempts_in_both_phases(tmp_path):
    store, archive = retained_run(tmp_path)
    sample = store.get_json(archive['baseline_id'])[0]
    row = {'request_id': sample['request_id'], 'case': sample['case'], 'mode': sample['mode'],
        'completion_id': store.put_bytes(sample['completion'].encode()), 'syntax_valid': False,
        'classification': 'INVALID_OUTPUT', 'channels': {}, 'error': 'strict protocol rejected'}
    summary = {'attempted': 1, 'syntax_valid': 0, 'audit_pass': 0, 'proxy_pass': 0,
        'fixed_wrong_adherent': 0, 'classifications': {'INVALID_OUTPUT': 1}}
    evaluation = {'kind': 'sft_development_evaluation', 'schema_version': 1,
        'training_archive_id': store.put_json(archive), 'image': 'not consulted for invalid packets',
        'phases': {phase: {'rows': [dict(row)], 'summary': dict(summary)} for phase in ('baseline', 'post_sft')},
        'limitations': ['Unit-only miniature archive, not a training run.']}
    assert verify_sft_evaluation(store, store.put_json(evaluation))['phases']['post_sft']['attempted'] == 1
    evaluation['phases']['post_sft']['rows'][0]['classification'] = 'NO_FALSE_REWARD'
    with pytest.raises(IntegrityError, match='relabelled'):
        verify_sft_evaluation(store, store.put_json(evaluation))


def test_matching_request_count_does_not_allow_reordered_prompts():
    requests = [{'id': 'a', 'prompt': 'first', 'case': 'x', 'mode': 'benign'},
                {'id': 'b', 'prompt': 'second', 'case': 'x', 'mode': 'benign'}]
    samples = [{'request_id': r['id'], 'prompt_id': 'sha256:' + hashlib.sha256(r['prompt'].encode()).hexdigest(),
                'case': r['case'], 'mode': r['mode'], 'completion': '{}'} for r in requests]
    check_samples(requests, samples)
    with pytest.raises(IntegrityError, match='linkage'):
        check_samples(requests, list(reversed(samples)))
