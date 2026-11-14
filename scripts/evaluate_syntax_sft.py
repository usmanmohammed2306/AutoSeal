"""Pair every saved baseline/post-SFT completion in fresh Mac Docker runs.

Known development prompts measure calibration only. This does not promote a
repair or satisfy the hidden-audit, three-seed GRPO experiment.
"""

import argparse
import json
from pathlib import Path

from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.model_artifacts import evaluate_packet
from autoseal.sft_archive import summarize, verify_sft_archive, verify_sft_evaluation
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    source = ContentAddressedStore(args.archive_root / 'evidence')
    archive_id = json.loads((args.archive_root / 'archive.json').read_bytes())['archive_id']
    checked = verify_sft_archive(source, archive_id)
    args.root.mkdir(parents=True, exist_ok=False)
    # Keep one CAS for the large immutable training archive. The evaluation
    # index points to it explicitly; no model or optimizer enters Docker.
    store = source
    archive = store.get_json(archive_id)
    config = store.get_json(archive['configuration_id'])
    phases = {name: {'rows': []} for name in ('baseline', 'post_sft')}
    samples = {'baseline': store.get_json(archive['baseline_id']), 'post_sft': store.get_json(archive['validation_id'])}
    image = image_identity(DEFAULT_IMAGE)
    # Alternate phase order by request, rather than evaluate all of one arm
    # first. Each candidate still gets two fresh isolated containers.
    for index, request in enumerate(config['validation_requests']):
        order = ('baseline', 'post_sft') if index % 2 == 0 else ('post_sft', 'baseline')
        for phase in order:
            sample = samples[phase][index]
            row = evaluate_packet(store, request=request, completion=sample['completion'], image=image)
            phases[phase]['rows'].append(row)
            print(json.dumps({'phase': phase, 'request': request['id'], 'classification': row['classification'],
                'syntax_valid': row['syntax_valid']}), flush=True)
        (args.root / 'progress.json').write_bytes(canonical_json(phases))
    for phase in phases.values():
        phase['summary'] = summarize(phase['rows'])
    report = {'kind': 'sft_development_evaluation', 'schema_version': 1,
        'training_archive_id': archive_id, 'image': image, 'phases': phases,
        'sources': {str(path): store.put_bytes(path.read_bytes()) for path in
            [Path(__file__), *sorted(Path('src/autoseal').glob('*.py'))]},
        'limitations': [checked['scope'],
            'Two benign and six targeted requests; targeted null-output adherence is reported separately.',
            'Wire validity, semantic task success and false rewards are separate outcomes.',
            'No Markdown stripping, JSON repair, dropped attempts or crash-as-rejection labels.',
            'The comparison uses stochastic generation with a common seed, not a powered efficacy study.']}
    identity = store.put_json(report)
    verified = verify_sft_evaluation(store, identity)
    (args.root / 'report.json').write_bytes(canonical_json({'evaluation_id': identity,
        'evidence_root': str((args.archive_root / 'evidence').resolve())}))
    print(json.dumps(verified))


if __name__ == '__main__':
    main()
