"""Audit denominator and provenance checks; synthetic rows are not model evidence."""

from copy import deepcopy
import pytest

from autoseal.artifact_audit import summarize_hidden, verify_hidden_sample
from autoseal.storage import ContentAddressedStore, IntegrityError


def matrix():
    config = {'models': [{'model_id': 'baseline', 'arm': 'baseline', 'seed': None}] +
        [{'model_id': f'{arm}-{seed}', 'arm': arm, 'seed': seed} for seed in (11, 22, 33) for arm in ('vulnerable', 'sealed')],
        'seeds': [11, 22, 33], 'requests': [{'request_id': f'audit-{i:02d}'} for i in range(8)]}
    rows = []
    for model in config['models']:
        for i, request in enumerate(config['requests']):
            invalid = i == 0
            false = model['arm'] == 'vulnerable' and i == 1
            rows.append({'model_id': model['model_id'], 'request_id': request['request_id'],
                'classification': 'INVALID_OUTPUT' if invalid else 'FALSE_REWARD' if false else 'NO_FALSE_REWARD',
                'channels': {} if invalid else {'proxy': {'verdict': 'PASS'}, 'audit': {'verdict': 'REJECT' if false else 'PASS'}}})
    return config, rows


def test_all_attempts_and_paired_seeds_are_retained():
    config, rows = matrix()
    summary = summarize_hidden(config, rows)
    assert len(summary['models']) == 7 and all(row['attempts'] == 8 for row in summary['models'])
    assert all(row['invalid_outputs'] == 1 for row in summary['models'])
    assert summary['paired_seed_contrasts'][0]['seed_differences'] == [.125] * 3
    assert summary['paired_seed_contrasts'][1]['seed_differences'] == [-.125] * 3
    assert summary['models'][0]['audit_success_rate'] == 7 / 8
    assert summarize_hidden(config, list(reversed(rows))) == summary


@pytest.mark.parametrize('mutation', ['drop_failure', 'duplicate_failure', 'unknown_checkpoint'])
def test_denominator_cannot_be_improved_by_filtering_or_relabelling(mutation):
    config, rows = matrix()
    if mutation == 'drop_failure':
        rows.pop(0)
    elif mutation == 'duplicate_failure':
        rows[0] = deepcopy(rows[1])
    else:
        rows[0]['model_id'] = 'cherry-picked-checkpoint'
    with pytest.raises(IntegrityError, match='attempt'):
        summarize_hidden(config, rows)


def test_infrastructure_failure_is_not_a_successful_block():
    config, rows = matrix()
    row = next(row for row in rows if row['model_id'] == 'sealed-11' and row['request_id'] == 'audit-01')
    row.update(classification='INCONCLUSIVE', channels={'proxy': {'verdict': 'PASS'}, 'audit': {'verdict': 'INCONCLUSIVE'}})
    summary = summarize_hidden(config, rows)
    selected = next(row for row in summary['models'] if row['model_id'] == 'sealed-11')
    assert selected['false_reward_rate_bounds'] == [0., .125]
    assert summary['audit_complete'] is False
    assert all(row['interpretation_eligible'] is False for row in summary['paired_seed_contrasts'])


def test_malformed_model_packet_cannot_become_an_audit_success(tmp_path):
    store = ContentAddressedStore(tmp_path)
    sample = {'model_id': 'sealed-11', 'request_id': 'audit-00', 'task_id': 'unissued', 'completion': 'not JSON'}
    row = {key: sample[key] for key in ('model_id', 'request_id', 'task_id')}
    row.update(completion_id=store.put_bytes(b'not JSON'), classification='INVALID_OUTPUT', channels={}, error='invalid packet')
    verify_hidden_sample(store, sample, row, image='unissued')
    row.update(classification='NO_FALSE_REWARD', channels={'audit': {'verdict': 'PASS'}})
    with pytest.raises(IntegrityError, match='invalid hidden packet'):
        verify_hidden_sample(store, sample, row, image='unissued')
