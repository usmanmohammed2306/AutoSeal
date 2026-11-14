"""Freeze a format-calibration pilot from reviewed authored examples.

Keeps benchmark tasks and hidden study audits out of the dataset. The saved
coding-model probe supplies actual model byte identities and syntax failures.
"""

import argparse
import json
from pathlib import Path

from autoseal.storage import ContentAddressedStore, canonical_json
from autoseal.syntax_dataset import SYSTEM, build_syntax_dataset, training_rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, choices=[16, 64, 128], default=16)
    parser.add_argument('--completion-only', action='store_true')
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.root / 'evidence')
    probe = json.loads((args.probe_root / 'generation-report.json').read_bytes())
    probe_config = json.loads((args.probe_root / 'configuration.json').read_bytes())
    if probe['status'] != 'COMPLETE' or probe['driver_id'] != probe_config['driver_id']:
        raise ValueError('a completed linked probe is required')
    revision, _ = build_syntax_dataset(store)
    examples = training_rows(store, revision)
    names = ['artifact_sft.py', 'training_runtime.py', 'artifact_sft.sbatch']
    root = Path(__file__).resolve().parent / 'sol'
    sources = {}
    for name in names:
        content = (root / name).read_bytes()
        sources[name] = store.put_bytes(content)
        (args.root / name).write_bytes(content)
    config = {'kind': 'artifact_sft_training', 'schema_version': 1, 'scope': 'FORMAT_CALIBRATION',
        'reason': 'The previous 7B calibration produced five invalid wire packets in eight attempts. No efficacy result exists.',
        'dataset_revision': revision, 'dataset_bytes_id': store.put_bytes(canonical_json(examples)),
        'training_examples': examples, 'model_files': probe['model_files'], 'model_source': probe_config['model_source'],
        'seed': 17, 'validation_seed': 17, 'max_steps': args.max_steps, 'max_length': 512, 'batch_size': 2,
        'learning_rate': .0002, 'temperature': .7, 'system': SYSTEM,
        'validation_requests': probe_config['requests'], 'sources': sources,
        'loss_scope': 'completion tokens only' if args.completion_only else 'all chat tokens on authored training examples',
        'completion_only_loss': args.completion_only,
        'pause_test': {'pause_at_step': args.max_steps // 2, 'resume_to_step': args.max_steps, 'same_configuration_required': True},
        'allocation_limit_per_attempt': {'a100_gpus': 1, 'wall_minutes': 10, 'host_memory_gib': 48},
        'source_probe_id': store.put_bytes((args.probe_root / 'generation-report.json').read_bytes()),
        'limitations': ['Single-seed development calibration, not the final three-seed comparison.',
            'The known validation prompts measure wire behavior; they are not hidden scientific audits.',
            'Examples are reviewed authored outputs, not human-annotated preference pairs.']}
    identity = store.put_json(config)
    (args.root / 'configuration.json').write_bytes(canonical_json(config))
    (args.root / 'index.json').write_text(json.dumps({'configuration_id': identity, 'dataset_revision': revision}, indent=2) + '\n')
    print(json.dumps({'configuration_id': identity, 'dataset_revision': revision, 'training_examples': len(examples)}))


if __name__ == '__main__':
    main()
