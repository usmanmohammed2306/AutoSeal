"""Transport-only checks. These do not run a trainer or a model."""

import importlib
from pathlib import Path

import pytest


@pytest.fixture
def client_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'scripts/sol'))
    return importlib.import_module('artifact_reward_client')


def configured(module, tmp_path):
    task = {'task_id': 'sha256:' + 'a' * 64, 'prompt_id': module.identity('prompt'),
        'prompt': 'compute the task', 'system': 'strict output'}
    manifest = {'seeds': [11], 'tasks': {task['task_id']: {'prompt_id': task['prompt_id']}},
        'max_batches_per_seed': 1, 'batch_size': 4, 'max_completion_bytes': 16384}
    identity = module.identity(manifest)
    client = module.ArtifactRewardClient(tmp_path, manifest, identity, [task], arm='sealed', seed=11, timeout=.01)
    kwargs = {'task_id': [task['task_id']] * 4,
        'prompts': [[{'role': 'system', 'content': task['system']}, {'role': 'user', 'content': task['prompt']}]] * 4}
    return client, task, identity, kwargs


def test_request_has_only_train_context_and_never_an_audit_payload(client_module, tmp_path):
    module = client_module
    client, task, manifest_id, kwargs = configured(module, tmp_path)
    with pytest.raises(TimeoutError):
        client(['{}'] * 4, **kwargs)
    paths = list((tmp_path / 'requests').glob('*.json'))
    assert len(paths) == 1
    import json
    body = json.loads(paths[0].read_bytes())
    assert set(body) == {'kind', 'schema_version', 'bridge_manifest_id', 'arm', 'seed', 'batch',
                         'task_id', 'prompt_id', 'completions'}
    assert body['task_id'] == task['task_id'] and body['arm'] == 'sealed'
    assert client.receipts == []


@pytest.mark.parametrize('change', ['prompt', 'task', 'mixed_group'])
def test_wrong_or_mixed_prompt_refused_before_publish(client_module, tmp_path, change):
    client, task, manifest_id, kwargs = configured(client_module, tmp_path)
    if change == 'prompt':
        kwargs['prompts'] = [[{'role': 'user', 'content': 'hidden audit prompt'}]] * 4
    elif change == 'task':
        kwargs['task_id'] = ['sha256:' + 'b' * 64] * 4
    else:
        kwargs['task_id'][0] = 'sha256:' + 'b' * 64
    with pytest.raises(ValueError):
        client(['{}'] * 4, **kwargs)
    assert not (tmp_path / 'requests').exists()


@pytest.mark.parametrize('failure', [False, True])
def test_response_must_match_request_and_infrastructure_failure_aborts(client_module, tmp_path, failure):
    module = client_module
    client, task, manifest_id, kwargs = configured(module, tmp_path)
    request = {'kind': 'artifact_study_reward_request', 'schema_version': 1,
        'bridge_manifest_id': manifest_id, 'arm': 'sealed', 'seed': 11, 'batch': 0,
        'task_id': task['task_id'], 'prompt_id': task['prompt_id'], 'completions': ['{}'] * 4}
    request_id = module.identity(request)
    response = {'kind': 'reward_response', 'schema_version': 1, 'request_id': request_id,
        'bridge_manifest_id': manifest_id, 'status': 'EVALUATOR_FAILURE' if failure else 'COMPLETE',
        'rewards': [None] * 4 if failure else [1., 0., 0., 1.],
        'outcomes': ['VERIFIER_FAILURE'] * 4 if failure else ['PASS', 'REJECT', 'REJECT', 'PASS'],
        'evidence_ids': ['sha256:' + 'c' * 64] * 4}
    module.write_once(tmp_path / 'responses' / (request_id[7:] + '.json'),
        module.canonical({'response_id': module.identity(response), 'response': response}))
    if failure:
        with pytest.raises(RuntimeError, match='do not substitute'):
            client(['{}'] * 4, **kwargs)
        assert client.receipts == []
    else:
        assert client(['{}'] * 4, **kwargs) == [1., 0., 0., 1.]
        assert client.receipts[0]['nonconstant'] is True
        with pytest.raises(RuntimeError, match='budget exhausted'):
            client(['{}'] * 4, **kwargs)


def test_shared_config_does_not_allow_cross_arm_or_seed_checkpoint_resume(client_module):
    module = importlib.import_module('artifact_grpo')
    proof = {'manifest_id': 'frozen-study', 'arm': 'vulnerable', 'seed': 11}
    module.check_resume_condition(proof, manifest_id='frozen-study', arm='vulnerable', seed=11)
    for values in [{'manifest_id': 'frozen-study', 'arm': 'sealed', 'seed': 11},
                   {'manifest_id': 'frozen-study', 'arm': 'vulnerable', 'seed': 22},
                   {'manifest_id': 'other-study', 'arm': 'vulnerable', 'seed': 11}]:
        with pytest.raises(ValueError, match='another reward arm, seed or study'):
            module.check_resume_condition(proof, **values)
