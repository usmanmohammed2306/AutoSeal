"""Freeze study inputs locally, then measure and admit training rewards.

Only training tasks are evaluated here. Committed audit inputs stay local and
are never exported to a trainer or used to select a repair. These instances
extend the authored training population, not the external-case denominator.
"""

import argparse
import json
from pathlib import Path

from autoseal.artifact_cases import ArtifactTask
from autoseal.artifact_pipeline import promote_artifact, validate_artifact_case
from autoseal.artifact_study import TaskBinding, freeze_task_pack, load_training_tasks
from autoseal.storage import ContentAddressedStore, canonical_json


def copy_store(source, destination):
    total = 0
    for index, path in enumerate(sorted((source.root / 'objects').glob('*/*'))):
        if index >= 16000 or path.is_symlink() or path.stat().st_size > 4 * 1024**2:
            raise ValueError('unexpected case archive inventory')
        content = source.get_bytes('sha256:' + path.name)
        total += len(content)
        if total > 64 * 1024**2:
            raise ValueError('case archive exceeds the migration byte bound')
        destination.put_bytes(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--prompt-version', type=int, choices=[1, 2], default=1)
    parser.add_argument('--input-count', type=int, choices=range(4, 33), default=24,
        help='Freeze task difficulty explicitly; changing it creates a new development population.')
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.root / 'evidence')
    dataset, hidden = freeze_task_pack(store, prompt_version=args.prompt_version, input_count=args.input_count)
    rows = load_training_tasks(store, dataset)
    bindings = {}
    index = {'kind': 'artifact_study_case_preparation', 'schema_version': 1,
        'dataset_revision': dataset, 'hidden_commitment': hidden, 'bindings': bindings,
        'status': 'INCOMPLETE', 'limitations': ['Eight authored training instances and eight committed audit instances.',
            'Training cases use existing seeded proxy mechanisms; not new external benchmark cases.',
            'Audits are hidden from training reward, not blind to the reference author.']}
    index['prompt_version'] = args.prompt_version
    index['input_count'] = args.input_count
    (args.root / 'index.json').write_bytes(canonical_json(index))
    for row in rows:
        task = ArtifactTask.model_validate(row['task'])
        directory = args.root / 'cases' / task.task_id
        validation_id = validate_artifact_case(directory, task)
        promotion = promote_artifact(directory, validation_id)
        source = ContentAddressedStore(directory / 'evidence')
        validation = source.get_json(validation_id)
        binding = TaskBinding(case_id=validation['case_id'], validation_id=validation_id,
            parent_revision=validation['parent_revision'], child_revision=validation['child_revision'],
            prompt_id=row['prompt_id'], seal_id=promotion['seal_evidence_id'], activation_id=promotion['activation_id'])
        copy_store(source, store)
        bindings[row['task_id']] = binding.model_dump(mode='json')
        (args.root / 'index.json').write_bytes(canonical_json(index))
        print(json.dumps({'task_id': task.task_id, 'validation_id': validation_id,
            'disposition': promotion['disposition']}), flush=True)
    index['status'] = 'COMPLETE'
    identity = store.put_json(index)
    (args.root / 'index.json').write_bytes(canonical_json({**index, 'preparation_id': identity}))
    print(json.dumps({'preparation_id': identity, 'training_tasks': len(bindings), 'audit_tasks': 8}))


if __name__ == '__main__':
    main()
