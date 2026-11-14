"""Check reward separation and durable replay on scripted controls only.

This is a contract check, not model output, a training seed or learned efficacy.
It uses its own manifest/ledger namespace and never consumes a model budget.
"""

import argparse
import json
from pathlib import Path

from autoseal.artifact_cases import load_case
from autoseal.artifact_runtime import load_files
from autoseal.artifact_study import StudyManifest, StudyRequest, StudyRewardWorker, load_training_tasks
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    store = ContentAddressedStore(args.root / 'evidence')
    prepared = json.loads((args.root / 'index.json').read_bytes())
    assert prepared['status'] == 'COMPLETE'
    training_id = store.put_json({'kind': 'SCRIPTED_REWARD_CONTRACT_ONLY', 'not_model_training': True})
    manifest = StudyManifest(scope='REWARD_PREFLIGHT', dataset_revision=prepared['dataset_revision'],
        hidden_commitment=prepared['hidden_commitment'], starting_checkpoint=training_id,
        training_configuration_id=training_id, seeds=(0,), max_batches_per_seed=1, tasks=prepared['bindings'])
    manifest_id = store.put_json(manifest.model_dump(mode='json'))
    worker = StudyRewardWorker(args.root, manifest_id)
    task_id = load_training_tasks(store, prepared['dataset_revision'])[0]['task_id']
    binding = manifest.tasks[task_id]
    case, _ = load_case(store, binding.case_id)
    completions = tuple(canonical_json({name: data.decode() for name, data in
        load_files(store, case['controls'][index]['candidate_id']).items()}).decode() for index in (0, 2, 4, 1))
    responses = {}
    for arm, expected in (('vulnerable', [1., 0., 1., 1.]), ('sealed', [1., 0., 0., 1.])):
        request = StudyRequest(bridge_manifest_id=manifest_id, arm=arm, seed=0, batch=0,
            task_id=task_id, prompt_id=binding.prompt_id, completions=completions)
        request_id = store.put_json(request.model_dump(mode='json'))
        response_id = worker.evaluate(request_id)
        response = store.get_json(response_id)
        assert response['status'] == 'COMPLETE' and response['rewards'] == expected
        assert worker.evaluate(request_id) == response_id
        conflict = request.model_copy(update={'completions': completions[::-1]})
        try:
            worker.evaluate(store.put_json(conflict.model_dump(mode='json')))
        except IntegrityError:
            pass
        else:
            raise AssertionError('conflicting batch replay was accepted')
        responses[arm] = {'request_id': request_id, 'response_id': response_id, 'rewards': response['rewards']}
    report = {'kind': 'scripted_artifact_study_reward_contract', 'schema_version': 1, 'status': 'PASSED',
        'manifest_id': manifest_id, 'responses': responses,
        'checks': ['Measured admitted reward separation', 'Identical request replays the same receipt',
            'Conflicting batch refuses before another execution', 'No hidden audit feedback in the reward response'],
        'limitations': ['Scripted controls only; not a model-produced exploit, optimizer run, study seed or hidden audit.']}
    identity = store.put_json(report)
    (args.root / 'reward-contract.json').write_bytes(canonical_json({'report_id': identity}))
    print(json.dumps({'report_id': identity, 'status': report['status'], 'responses': responses}))


if __name__ == '__main__':
    main()
