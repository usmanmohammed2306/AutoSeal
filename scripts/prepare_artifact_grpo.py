"""Export only frozen train prompts and trusted code for a bounded GRPO run.

The export excludes audit inputs, oracle outputs and benchmark sources. The
Mac broker retains the complete admitted-repair and SFT lineage archives.
"""

import argparse
import json
from pathlib import Path

from autoseal.artifact_study import StudyManifest, StudyRewardWorker, load_training_tasks
from autoseal.artifact_study_archive import verify_study_archive
from autoseal.sft_archive import verify_sft_evaluation
from autoseal.storage import ContentAddressedStore, canonical_json
from autoseal.syntax_dataset import SYSTEM


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--sft-archive-root', type=Path, required=True)
    parser.add_argument('--sft-evaluation-id', required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--scope', choices=['REWARD_PREFLIGHT', 'FROZEN_PAIRED_STUDY'], default='REWARD_PREFLIGHT')
    parser.add_argument('--preflight-archive-id', help='Required final-study readiness proof, never a scripted contract.')
    args = parser.parse_args()
    if args.scope == 'FROZEN_PAIRED_STUDY' and not args.preflight_archive_id:
        parser.error('the final study requires a verified responsive model preflight')
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.case_root / 'evidence')
    parent_store = ContentAddressedStore(args.sft_archive_root / 'evidence')
    checked = verify_sft_evaluation(parent_store, args.sft_evaluation_id)
    parent_eval = parent_store.get_json(args.sft_evaluation_id)
    parent_archive = parent_store.get_json(parent_eval['training_archive_id'])
    sft = parent_store.get_json(parent_archive['report_id'])
    sft_config = parent_store.get_json(parent_archive['configuration_id'])
    # Retain complete parent lineage locally. No optimizer or hidden data is
    # part of the exported configuration sent to the GPU node.
    total = 0
    for path in sorted((parent_store.root / 'objects').glob('*/*')):
        if path.is_symlink():
            raise ValueError('unexpected symlink in the parent training archive')
        raw = parent_store.get_bytes('sha256:' + path.name); total += len(raw)
        if total > 256 * 1024**2:
            raise ValueError('parent training archive exceeds the local copy budget')
        store.put_bytes(raw)
    prepared = json.loads((args.case_root / 'index.json').read_bytes())
    if prepared['status'] != 'COMPLETE':
        raise ValueError('all train environments must pass admission before freeze')
    tasks = load_training_tasks(store, prepared['dataset_revision'])
    starting = store.put_json({'kind': 'shared_sft_starting_checkpoint', 'schema_version': 1,
        'base_model_identity': sft['base_identity'], 'model_source': sft_config['model_source'],
        'adapter_files': sft['adapter_files'], 'parent_sft_archive_id': parent_eval['training_archive_id'],
        'parent_calibration_evaluation_id': args.sft_evaluation_id,
        'optimizer_policy': 'Reset optimizer for both GRPO arms; identical shared SFT model weights.'})
    if args.scope == 'FROZEN_PAIRED_STUDY':
        readiness = verify_study_archive(store, args.preflight_archive_id)
        preflight = store.get_json(args.preflight_archive_id)
        preflight_manifest = StudyManifest.model_validate(store.get_json(preflight['manifest_id']))
        if (readiness['scope'] != 'REWARD_PREFLIGHT' or not readiness['training_complete']
                or preflight_manifest.dataset_revision != prepared['dataset_revision']
                or preflight_manifest.starting_checkpoint != starting):
            raise ValueError('final study preflight uses another dataset, checkpoint or incomplete condition matrix')
        if readiness['nonconstant_reward_groups'] == 0:
            raise ValueError('final study blocked: the model preflight has no nonconstant rewards')
        responsive = False
        for condition in preflight['conditions'].values():
            report = store.get_json(condition['report_id'])
            responsive |= any(row.get('grad_norm', 0.) > 0 for row in report.get('log_history', []))
        if not responsive:
            raise ValueError('final study blocked: no nonzero model gradient was recorded')
    sol = Path(__file__).resolve().parent / 'sol'
    names = ['artifact_grpo.py', 'artifact_campaign.py', 'artifact_reward_client.py', 'reward_client.py',
        'reward_exchange.py', 'training_runtime.py', 'artifact_grpo.sbatch']
    sources = {}
    for name in names:
        raw = (sol / name).read_bytes(); sources[name] = store.put_bytes(raw)
        (args.root / name).write_bytes(raw)
    preflight = args.scope == 'REWARD_PREFLIGHT'
    config = {'kind': 'artifact_grpo_training', 'schema_version': 1, 'starting_checkpoint': starting,
        'model_files': sft_config['model_files'], 'model_source': sft_config['model_source'],
        'warm_adapter_files': sft['adapter_files'], 'sources': sources,
        'max_steps': 2 if preflight else 8, 'max_prompt_tokens': 2048, 'max_completion_tokens': 256,
        'learning_rate': .00002, 'temperature': .9,
        'tasks': [{key: row[key] for key in ('task_id', 'prompt_id', 'prompt')} | {'system': SYSTEM} for row in tasks],
        'candidate_sampling': 'Natural semantic-task prompts with white-box visible proxy; no forced wrong deliverable.',
        'reward_scheme': 'Binary proxy/sealed verdict; invalid strict packet is 0, verifier failure aborts.',
        'stop_rule': 'Complete the frozen bounded condition matrix; a preflight cannot authorize a final study by itself.',
        'exclusion_rule': 'Retain failed, interrupted and nonconstant-free runs; no retries pooled into another seed.',
        'calibration_limitations': checked['limitations'],
        'allocation_ceiling': {'a100_gpus': 1, 'host_memory_gib': 48, 'wall_minutes': 15 if preflight else 45}}
    config['analysis_protocol'] = {'kind': 'artifact_study_analysis_protocol', 'schema_version': 1,
        'implementation_id': store.put_bytes((Path(__file__).resolve().parents[1] / 'src/autoseal/artifact_audit.py').read_bytes()),
        'primary': ['Independent hidden-audit task passes per eight attempts',
            'Proxy-pass/audit-reject false rewards per eight attempts'],
        'unit': 'Paired training seed; all eight committed audit instances per checkpoint',
        'contrast': 'sealed minus vulnerable; show all seed values and descriptive paired-seed bootstrap percentiles',
        'missing': 'Invalid packets are task failures. Inconclusive results remain visible and prevent a complete audit conclusion.',
        'baseline': 'One shared SFT model, evaluated once on the same committed prompts and greedy token budget',
        'selection': 'Use the last frozen optimizer checkpoint from every seed and arm, including null or adverse results.',
        'interpretation': 'No population, external-benchmark, significance or generalization claim from three seeds and eight authored instances.'}
    if not preflight:
        config['preflight_archive_id'] = args.preflight_archive_id
    config_id = store.put_json(config)
    manifest = StudyManifest(scope=args.scope, dataset_revision=prepared['dataset_revision'],
        hidden_commitment=prepared['hidden_commitment'], starting_checkpoint=starting,
        training_configuration_id=config_id, tasks=prepared['bindings'], seeds=(11,) if preflight else (11, 22, 33),
        max_batches_per_seed=config['max_steps'])
    manifest_id = store.put_json(manifest.model_dump(mode='json'))
    # Re-check train membership now, before any upload or allocation.
    StudyRewardWorker(args.case_root, manifest_id)
    envelope = {'configuration_id': config_id, 'training_configuration': config,
        'manifest_id': manifest_id, 'manifest': manifest.model_dump(mode='json')}
    (args.root / 'configuration.json').write_bytes(canonical_json(envelope))
    (args.root / 'index.json').write_bytes(canonical_json({'manifest_id': manifest_id, 'configuration_id': config_id,
        'scope': args.scope, 'hidden_inputs_exported': False, 'parent_sft_archive_id': parent_eval['training_archive_id']}))
    print(json.dumps({'manifest_id': manifest_id, 'configuration_id': config_id,
        'scope': args.scope, 'train_tasks': 8, 'audit_inputs_exported': 0}))


if __name__ == '__main__':
    main()
