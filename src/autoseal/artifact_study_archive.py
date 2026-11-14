"""Recompute the training-only study archive from raw Mac reward evidence.

This verifier never executes a candidate or deserializes an optimizer. It
cannot substitute for a post-checkpoint hidden audit or an efficacy analysis.
"""

from __future__ import annotations

from collections import Counter

from autoseal.artifact_pipeline import resolve_artifact, verify_artifact_validation
from autoseal.artifact_runtime import freeze_files
from autoseal.artifact_study import StudyManifest, StudyRequest, load_training_tasks
from autoseal.model_artifacts import parse_packet
from autoseal.revisions import RevisionTransition
from autoseal.seal import verify_seal
from autoseal.sft_archive import _verify_files, verify_sft_evaluation
from autoseal.storage import IntegrityError, canonical_json
from autoseal.syntax_dataset import SYSTEM


def require(condition, message):
    if not condition:
        raise IntegrityError(message)


def verify_study_context(store, manifest_id):
    manifest = StudyManifest.model_validate(store.get_json(manifest_id))
    config = store.get_json(manifest.training_configuration_id)
    require(config['kind'] == 'artifact_grpo_training' and config['schema_version'] == 1,
        'unsupported artifact training configuration')
    tasks = load_training_tasks(store, manifest.dataset_revision)
    require({row['task_id'] for row in tasks} == set(manifest.tasks)
        and config['max_steps'] == manifest.max_batches_per_seed, 'study configuration membership or budget changed')
    projected = [{key: row[key] for key in ('task_id', 'prompt_id', 'prompt')} | {'system': SYSTEM} for row in tasks]
    require(len(config['tasks']) == len(tasks) and config['tasks'] == projected, 'exported train prompts differ from the reviewed split')
    for digest in config['sources'].values():
        store.get_bytes(digest)
    starting = store.get_json(manifest.starting_checkpoint)
    parent_id = starting['parent_calibration_evaluation_id']
    verify_sft_evaluation(store, parent_id)
    parent = store.get_json(parent_id)
    archive = store.get_json(parent['training_archive_id'])
    parent_config, parent_report = store.get_json(archive['configuration_id']), store.get_json(archive['report_id'])
    require(starting['kind'] == 'shared_sft_starting_checkpoint'
        and config['starting_checkpoint'] == manifest.starting_checkpoint
        and config['warm_adapter_files'] == starting['adapter_files'] == parent_report['adapter_files']
        and config['model_files'] == parent_config['model_files']
        and config['model_source'] == parent_config['model_source']
        and starting['base_model_identity'] == parent_report['base_identity']
        and starting['parent_sft_archive_id'] == parent['training_archive_id'],
        'study starting weights differ from their verified shared SFT parent')
    for task in tasks:
        binding = manifest.tasks[task['task_id']]
        validation = verify_artifact_validation(store, binding.validation_id)
        seal = verify_seal(store, binding.seal_id, child_revision=binding.child_revision)
        activation = RevisionTransition.model_validate(store.get_json(binding.activation_id))
        require(binding.prompt_id == task['prompt_id'] and seal.validation_identity == binding.validation_id
            and validation['case_id'] == binding.case_id
            and validation['parent_revision'] == binding.parent_revision
            and validation['child_revision'] == binding.child_revision
            and all(validation['gates'].values()) and activation.before == binding.parent_revision
            and activation.after == binding.child_revision and activation.admission_identity == binding.seal_id
            and activation.action == 'activate'
            and activation.restored_artifacts == store.get_json(binding.child_revision)['artifacts'],
            'study training reward lacks matching admitted environment evidence')
    return manifest, config


def verify_training_batch(store, manifest, manifest_id, request_id, response_id):
    request = StudyRequest.model_validate(store.get_json(request_id))
    require(request.bridge_manifest_id == manifest_id and request.seed in manifest.seeds
        and request.batch < manifest.max_batches_per_seed and request.task_id in manifest.tasks,
        'archived reward request crossed its frozen condition')
    binding = manifest.tasks[request.task_id]
    require(request.prompt_id == binding.prompt_id, 'archived reward request prompt changed')
    response = store.get_json(response_id)
    require(response['kind'] == 'reward_response' and response['schema_version'] == 1
        and response['request_id'] == request_id and response['bridge_manifest_id'] == manifest_id
        and len(response['rewards']) == len(response['outcomes']) == len(response['evidence_ids']) == 4
        and response['status'] in {'COMPLETE', 'EVALUATOR_FAILURE'},
        'archived training response differs from its request')
    revision = binding.parent_revision if request.arm == 'vulnerable' else binding.child_revision
    channel = 'proxy' if request.arm == 'vulnerable' else 'sealed'
    for text, reward, outcome, ref in zip(request.completions, response['rewards'], response['outcomes'], response['evidence_ids']):
        require(len(text.encode()) <= manifest.max_completion_bytes, 'archived completion exceeded the frozen byte budget')
        evidence = store.get_json(ref)
        try:
            files = parse_packet(text)
        except (ValueError, TypeError, UnicodeError):
            require(outcome == 'INVALID_OUTPUT' and type(reward) in (int, float) and reward == 0.
                and evidence['kind'] == 'invalid_artifact_study_output'
                and store.get_bytes(evidence['completion_id']) == text.encode(), 'invalid output was given another reward')
            continue
        candidate = freeze_files(store, files)
        require(evidence['candidate_id'] == candidate and evidence['task_id'] == request.task_id
            and evidence['revision_id'] == revision, 'training reward used another candidate, task or arm revision')
        if outcome == 'VERIFIER_FAILURE':
            require(reward is None and evidence['kind'] == 'artifact_study_evaluation_failure' and bool(evidence['error']),
                'verifier failure became a scalar training label')
            continue
        require(evidence['kind'] == 'artifact_study_training_reward' and evidence['channel'] == channel,
            'training reward contains another evaluator channel')
        result = resolve_artifact(store, evidence['result_id'], case_id=binding.case_id,
            candidate_id=candidate, revision_id=revision, channel=channel)
        expected = 1. if result['verdict'] == 'PASS' else 0.
        require(outcome == evidence['verdict'] == result['verdict'] and type(reward) in (int, float) and reward == expected,
            'training reward contradicts its raw admitted-verifier result')
    complete = all(value is not None for value in response['rewards'])
    require((response['status'] == 'COMPLETE') == complete, 'reward failure status changed')
    return request, response


def verify_study_archive(store, identity):
    archive = store.get_json(identity)
    require(archive['kind'] == 'artifact_study_training_archive' and archive['schema_version'] == 1,
        'unsupported study training archive')
    manifest_id = archive['manifest_id']
    manifest, config = verify_study_context(store, manifest_id)
    campaign = store.get_json(archive['campaign_id'])
    require(campaign['manifest_id'] == manifest_id and campaign['configuration_id'] == manifest.training_configuration_id
        and campaign['scope'] == manifest.scope, 'campaign differs from its frozen study')
    matrix = {(arm, seed) for arm in ('vulnerable', 'sealed') for seed in manifest.seeds}
    require(len(campaign['conditions']) == len(matrix)
        and {(row['arm'], row['seed']) for row in campaign['conditions']} == matrix, 'campaign condition matrix is incomplete')
    require(set(archive['conditions']) == {f"{row['arm']}-{row['seed']}" for row in campaign['conditions'] if row['status'] != 'NOT_RUN'},
        'study archive hides or adds a condition result')
    batches = {}
    for row in archive['broker_batches']:
        key = (row['arm'], row['seed'], row['batch'])
        require(key not in batches and row['seed'] in manifest.seeds and row['batch'] < manifest.max_batches_per_seed,
            'broker ledger repeats or exceeds a frozen condition')
        request = StudyRequest.model_validate(store.get_json(row['request_id']))
        require((request.arm, request.seed, request.batch) == key, 'broker ledger key differs from its request')
        response = None
        if row['response_id'] is not None:
            request, response = verify_training_batch(store, manifest, manifest_id, row['request_id'], row['response_id'])
        batches[key] = (row, response)
    conditions = []
    for planned in campaign['conditions']:
        name = f"{planned['arm']}-{planned['seed']}"
        if planned['status'] == 'NOT_RUN':
            require(name not in archive['conditions'], 'unrun condition contains a hidden result')
            conditions.append({**planned, 'attempted_outputs': 0}); continue
        condition = archive['conditions'][name]
        if planned['status'] == 'FAILED_WITHOUT_REPORT':
            require(condition.get('missing_report') is True and planned['process_exit_code'] != 0,
                'missing condition report was hidden behind a success')
            attempted = sum(key[:2] == (planned['arm'], planned['seed']) for key in batches) * 4
            conditions.append({**planned, 'attempted_outputs': attempted,
                'error': 'Trusted condition process exited without its model report; no optimizer success inferred.'})
            continue
        report = store.get_json(condition['report_id'])
        require(condition['report_id'] == planned['report_id'], 'condition report differs from the campaign commitment')
        expected = {'kind': 'artifact_grpo_training_report', 'schema_version': 1, 'scope': manifest.scope,
            'configuration_id': manifest.training_configuration_id, 'manifest_id': manifest_id,
            'arm': planned['arm'], 'seed': planned['seed'], 'dataset_revision': manifest.dataset_revision,
            'hidden_commitment': manifest.hidden_commitment, 'starting_checkpoint': manifest.starting_checkpoint}
        require(all(report[key] == value for key, value in expected.items()) and report['status'] == planned['status'],
            'condition report changes its model, dataset, arm, seed or status')
        accepted = report['batch_receipts']
        require(len(accepted) <= manifest.max_batches_per_seed and [row['batch'] for row in accepted] == list(range(len(accepted))),
            'condition reward history is not a bounded contiguous prefix')
        rewards, outcomes, contrast = [], [], 0
        for row in accepted:
            ledger, response = batches[(report['arm'], report['seed'], row['batch'])]
            require(response is not None and response['status'] == 'COMPLETE'
                and row['request_id'] == ledger['request_id'] and row['response_id'] == ledger['response_id']
                and row['rewards'] == response['rewards'] and row['outcomes'] == response['outcomes'],
                'trainer accepted another reward response or silently accepted verifier failure')
            request = store.get_json(row['request_id'])
            require(row['task_id'] == request['task_id'] and row['prompt_id'] == request['prompt_id'], 'trainer reward history task changed')
            varied = len(set(response['rewards'])) > 1
            require(row['nonconstant'] is varied, 'reward contrast flag contradicts actual scalars')
            contrast += varied; rewards += response['rewards']; outcomes += response['outcomes']
        require(report['nonconstant_reward_groups'] == contrast, 'condition contrast count differs from accepted rewards')
        if report['status'] == 'COMPLETE':
            require(report['error'] is None and report['global_step'] == len(accepted) == manifest.max_batches_per_seed,
                'completed condition lacks its full optimizer/reward budget')
            proof = report['checkpoint_manifest']
            require(all(proof[key] == value for key, value in {'configuration_id': manifest.training_configuration_id,
                'dataset_id': manifest.dataset_revision, 'base_identity': manifest.starting_checkpoint,
                'manifest_id': manifest_id, 'arm': report['arm'], 'seed': report['seed'],
                'global_step': report['global_step']}.items()), 'condition checkpoint crossed another arm, seed or dataset')
            _verify_files(store, proof['checkpoint_files'], condition['checkpoint_files'])
            _verify_files(store, report['adapter_files'], condition['adapter_files'])
            require(store.get_json(condition['checkpoint_files']['autoseal-reward-receipts.json']) == accepted,
                'optimizer checkpoint differs from its reward history')
            state = store.get_json(condition['checkpoint_files']['trainer_state.json'])
            require(state['global_step'] == report['global_step'], 'optimizer checkpoint step differs')
            require(condition['adapter_files']['adapter_model.safetensors'] == condition['checkpoint_files']['adapter_model.safetensors'],
                'final exported model differs from the optimizer checkpoint')
            adapter_id = condition['adapter_files']['adapter_model.safetensors']
        else:
            require(bool(report['error']), 'failed condition omits its error')
            adapter_id = None
        observed_batches = [value for key, value in batches.items() if key[:2] == (report['arm'], report['seed'])]
        conditions.append({'arm': report['arm'], 'seed': report['seed'], 'status': report['status'],
            'global_step': report['global_step'], 'accepted_outputs': len(outcomes),
            'attempted_outputs': 4 * len(observed_batches), 'outcomes': dict(Counter(outcomes)),
            'reward_sum': sum(rewards), 'nonconstant_reward_groups': contrast, 'adapter_id': adapter_id,
            'failed_or_pending_groups': sum(response is None or response['status'] != 'COMPLETE' for _, response in observed_batches),
            'error': report['error']})
    complete = all(row['status'] == 'COMPLETE' for row in conditions)
    require(campaign['status'] in {'COMPLETE', 'FAILED'}, 'campaign lacks a terminal completion or failure record')
    require((campaign['status'] == 'COMPLETE') == complete, 'campaign completion status contradicts its conditions')
    if complete:
        require(campaign['nonconstant_reward_groups'] == sum(row['nonconstant_reward_groups'] for row in conditions),
            'campaign contrast count contradicts verified scalar rewards')
    for ref in archive['raw_logs'].values():
        store.get_bytes(ref)
    scheduler = store.get_bytes(archive['scheduler_id']).decode()
    if complete:
        jobs = {str(store.get_json(value['report_id'])['slurm_job_id']) for value in archive['conditions'].values()}
        require(len(jobs) == 1, 'one-allocation campaign reports different scheduler jobs')
        for job in jobs:
            rows = [line.split() for line in scheduler.splitlines() if line.split() and line.split()[0] == job]
            require(len(rows) == 1 and rows[0][1] == 'COMPLETED' and rows[0][-1] == '0:0',
                'completed training campaign lacks successful scheduler completion')
    return {'archive_id': identity, 'manifest_id': manifest_id, 'scope': manifest.scope,
        'training_complete': complete, 'conditions': conditions,
        'nonconstant_reward_groups': sum(row.get('nonconstant_reward_groups', 0) for row in conditions),
        'hidden_audit_completed': False, 'efficacy_established': False,
        'limitations': ['This checks the training path and admitted scalar rewards, not semantic success on hidden tasks.',
            'Failed, pending and unrun groups stay visible. Scripted contract checks are outside this model cohort.',
            'A one-seed preflight never satisfies the final three-seed study.']}
