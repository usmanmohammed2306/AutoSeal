"""Export committed audit prompts only after every final checkpoint is frozen.

Preflights, incomplete matrices and fewer than three seeds are refused before
any audit configuration is written. Gold outputs remain on the Mac.
"""

import argparse
import json
from pathlib import Path, PurePosixPath

from autoseal.artifact_audit import require_final_matrix
from autoseal.artifact_study import StudyManifest
from autoseal.artifact_study_archive import verify_study_archive
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json
from autoseal.syntax_dataset import SYSTEM
from autoseal.training_data import DatasetRevision, Split


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--training-archive-id', required=True)
    parser.add_argument('--remote-campaign-root', required=True)
    parser.add_argument('--warm-adapter', required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    for path in (args.remote_campaign_root, args.warm_adapter):
        if not PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:
            raise ValueError('audit model paths must name absolute owned training outputs')
    store = ContentAddressedStore(args.case_root / 'evidence')
    checked = verify_study_archive(store, args.training_archive_id)
    require_final_matrix(checked)
    archive = store.get_json(args.training_archive_id)
    manifest = StudyManifest.model_validate(store.get_json(archive['manifest_id']))
    training = store.get_json(manifest.training_configuration_id)
    hidden = store.get_json(manifest.hidden_commitment)
    dataset = DatasetRevision.model_validate(store.get_json(manifest.dataset_revision))
    expected = [store.get_json(item.content_id) for item in dataset.items if item.split is Split.AUDIT]
    if (hidden['kind'] != 'artifact_study_hidden_pack' or hidden['schema_version'] != 1
            or hidden['dataset_revision'] != manifest.dataset_revision or hidden['records'] != expected or len(expected) != 8):
        raise IntegrityError('audit pack differs from the pre-training commitment')
    requests = [{'request_id': f'audit-{index:02d}', 'task_id': row['task_id'], 'prompt_id': row['prompt_id'],
        'prompt': store.get_bytes(row['prompt_id']).decode()} for index, row in enumerate(expected)]
    models = [{'model_id': 'shared-sft-baseline', 'arm': 'baseline', 'seed': None,
        'adapter_files': training['warm_adapter_files'], 'remote_path': args.warm_adapter}]
    for row in sorted(checked['conditions'], key=lambda value: (value['seed'], value['arm'])):
        name = f"{row['arm']}-{row['seed']}"
        condition = archive['conditions'][name]
        report = store.get_json(condition['report_id'])
        models.append({'model_id': name, 'arm': row['arm'], 'seed': row['seed'],
            'adapter_files': report['adapter_files'], 'remote_path': str(PurePosixPath(args.remote_campaign_root) / name / 'adapter'),
            'condition_report_id': condition['report_id']})
    args.root.mkdir(parents=True, exist_ok=False)
    sources = {}
    for name in ('artifact_audit.py', 'artifact_audit.sbatch', 'training_runtime.py'):
        content = (Path(__file__).parent / 'sol' / name).read_bytes()
        sources[name] = store.put_bytes(content); (args.root / name).write_bytes(content)
    config = {'kind': 'artifact_study_audit_generation', 'schema_version': 1,
        'scope': 'POST_CHECKPOINT_HIDDEN_AUDIT', 'training_archive_id': args.training_archive_id,
        'manifest_id': archive['manifest_id'], 'hidden_commitment': manifest.hidden_commitment,
        'model_files': training['model_files'], 'model_source': training['model_source'],
        'seeds': list(manifest.seeds), 'models': models, 'requests': requests, 'system': SYSTEM,
        'decoding': {'do_sample': False, 'seed': 20261113, 'max_new_tokens': 256, 'max_input_tokens': 2048},
        'sources': sources, 'allocation_ceiling': {'a100_gpus': 1, 'host_memory_gib': 48, 'wall_minutes': 20},
        'retry_policy': 'Keep failed attempts. Never tune a model or reward after inspecting these audit outputs.',
        'limitations': ['Eight authored unseen input instances, not external benchmark or algorithm generalization.',
            'The shared SFT baseline is one model, not three independent baselines.',
            'Gold outputs stay on Mac; this generation job cannot decide task success.']}
    config_id = store.put_json(config)
    (args.root / 'configuration.json').write_bytes(canonical_json(config))
    (args.root / 'index.json').write_bytes(canonical_json({'configuration_id': config_id,
        'training_archive_id': args.training_archive_id, 'model_count': len(models), 'audit_prompts': len(requests)}))
    print(json.dumps({'configuration_id': config_id, 'model_count': len(models), 'audit_prompts': len(requests)}))


if __name__ == '__main__':
    main()
