"""Offline tamper checks on retained study contexts and scripted receipts.

These tests never claim that the scripted controls came from a model.
"""

import json
from pathlib import Path

import pytest

from autoseal.artifact_study import StudyManifest
from autoseal.artifact_study_archive import verify_study_archive, verify_study_context, verify_training_batch
from autoseal.storage import ContentAddressedStore, IntegrityError


ROOT = Path(__file__).resolve().parents[2] / 'research/experiments/2026-11-13-artifact-admission/study-cases-02'
pytestmark = pytest.mark.archive


@pytest.fixture
def archive():
    if not (ROOT / 'export-preflight-01/index.json').exists() or not (ROOT / 'reward-contract.json').exists():
        pytest.skip('separately retained admitted study preparation not available')
    store = ContentAddressedStore(ROOT / 'evidence')
    manifest_id = json.loads((ROOT / 'export-preflight-01/index.json').read_bytes())['manifest_id']
    return store, manifest_id


def test_all_training_rewards_bind_the_reviewed_shared_parent(archive):
    store, manifest_id = archive
    manifest, config = verify_study_context(store, manifest_id)
    assert manifest.scope == 'REWARD_PREFLIGHT' and len(manifest.tasks) == 8
    assert len(config['tasks']) == 8


@pytest.mark.parametrize('change', ['system', 'prompt', 'starting_adapter'])
def test_forged_context_does_not_match_the_reviewed_parent(archive, change):
    store, manifest_id = archive
    manifest = store.get_json(manifest_id)
    config = store.get_json(manifest['training_configuration_id'])
    if change == 'system':
        config['tasks'][0]['system'] = 'an unreviewed instruction'
    elif change == 'prompt':
        first = next(iter(manifest['tasks']))
        manifest['tasks'][first]['prompt_id'] = store.put_bytes(b'unreviewed prompt')
    else:
        config['warm_adapter_files']['adapter_model.safetensors']['sha256'] = '0' * 64
    manifest['training_configuration_id'] = store.put_json(config)
    with pytest.raises(IntegrityError):
        verify_study_context(store, store.put_json(manifest))


def scripted(store):
    report_id = json.loads((ROOT / 'reward-contract.json').read_bytes())['report_id']
    report = store.get_json(report_id)
    manifest_id = report['manifest_id']
    manifest = StudyManifest.model_validate(store.get_json(manifest_id))
    return report, manifest, manifest_id


def test_raw_scripted_discrimination_is_recomputed_not_trusted(archive):
    store, _ = archive
    report, manifest, manifest_id = scripted(store)
    for arm, expected in [('vulnerable', [1., 0., 1., 1.]), ('sealed', [1., 0., 0., 1.])]:
        refs = report['responses'][arm]
        _, response = verify_training_batch(store, manifest, manifest_id, refs['request_id'], refs['response_id'])
        assert response['rewards'] == expected


def test_false_positive_scalar_cannot_replace_the_raw_sealed_verdict(archive):
    store, _ = archive
    report, manifest, manifest_id = scripted(store)
    refs = report['responses']['sealed']
    response = store.get_json(refs['response_id'])
    response['rewards'][2] = 1.
    with pytest.raises(IntegrityError, match='contradicts'):
        verify_training_batch(store, manifest, manifest_id, refs['request_id'], store.put_json(response))


def test_archived_reward_cannot_be_attached_to_an_audit_task(archive):
    store, _ = archive
    report, manifest, manifest_id = scripted(store)
    refs = report['responses']['sealed']
    request = store.get_json(refs['request_id'])
    hidden = store.get_json(manifest.hidden_commitment)['records'][0]
    request['task_id'], request['prompt_id'] = hidden['task_id'], hidden['prompt_id']
    with pytest.raises(IntegrityError, match='frozen condition'):
        verify_training_batch(store, manifest, manifest_id, store.put_json(request), refs['response_id'])


@pytest.fixture
def model_archive(archive):
    store, _ = archive
    path = ROOT.parent / 'study-preflight-archive-01/archive.json'
    if not path.exists():
        pytest.skip('separately retained actual GRPO preflight archive not available')
    return store, json.loads(path.read_bytes())['archive_id']


def test_actual_null_model_preflight_is_not_promoted_to_learning_evidence(model_archive):
    store, identity = model_archive
    checked = verify_study_archive(store, identity)
    assert checked['training_complete'] is True and checked['scope'] == 'REWARD_PREFLIGHT'
    assert checked['nonconstant_reward_groups'] == 0
    assert checked['hidden_audit_completed'] is False and checked['efficacy_established'] is False
    assert [row['attempted_outputs'] for row in checked['conditions']] == [8, 8]
    assert [row['outcomes'] for row in checked['conditions']] == [{'INVALID_OUTPUT': 2, 'REJECT': 6}] * 2
    assert len({row['adapter_id'] for row in checked['conditions']}) == 1


@pytest.mark.parametrize('change', ['seed', 'optimizer', 'scheduler', 'missing_condition'])
def test_forged_complete_model_archive_is_refused(model_archive, change):
    store, identity = model_archive
    record = store.get_json(identity)
    if change == 'scheduler':
        record['scheduler_id'] = store.put_bytes(store.get_bytes(record['scheduler_id']).replace(b'COMPLETED', b'TIMEOUT'))
    elif change == 'missing_condition':
        record['conditions'].pop(next(iter(record['conditions'])))
    else:
        name = next(iter(record['conditions']))
        condition = record['conditions'][name]
        if change == 'optimizer':
            condition['checkpoint_files']['optimizer.pt'] = store.put_bytes(b'untrusted replaced optimizer bytes')
        else:
            report = store.get_json(condition['report_id'])
            report['checkpoint_manifest']['seed'] = 22
            condition['report_id'] = store.put_json(report)
            campaign = store.get_json(record['campaign_id'])
            next(row for row in campaign['conditions'] if f"{row['arm']}-{row['seed']}" == name)['report_id'] = condition['report_id']
            record['campaign_id'] = store.put_json(campaign)
    with pytest.raises((IntegrityError, KeyError)):
        verify_study_archive(store, store.put_json(record))
