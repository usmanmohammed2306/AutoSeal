"""Evaluate frozen hidden generations in Mac Docker, then recount raw receipts.

No trainer, model selector or reward callback imports this command. A failed
Docker evaluation remains visible and prevents a complete audit conclusion.
"""

import argparse
import json
from pathlib import Path

from autoseal.artifact_audit import evaluate_hidden_sample, summarize_hidden, verify_audit_generation, verify_hidden_evaluation
from autoseal.docker_fixture import DEFAULT_IMAGE, image_identity
from autoseal.storage import ContentAddressedStore, IntegrityError, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--generation-archive-id', required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    store = ContentAddressedStore(args.case_root / 'evidence')
    config, report = verify_audit_generation(store, args.generation_archive_id)
    if report['status'] != 'COMPLETE':
        raise IntegrityError('retain incomplete generations; do not turn their surviving samples into a full comparison')
    args.root.mkdir(parents=True, exist_ok=False)
    image = image_identity(DEFAULT_IMAGE)
    rows, refs, contexts = [], [], {}
    for sample in report['samples']:
        row = evaluate_hidden_sample(store, sample, image=image, contexts=contexts)
        rows.append(row); refs.append(store.put_json(row))
        (args.root / 'progress.json').write_bytes(canonical_json({'outcome_ids': refs, 'expected_attempts': len(report['samples'])}))
        print(json.dumps({key: row[key] for key in ('model_id', 'request_id', 'classification')}), flush=True)
    summary = summarize_hidden(config, rows)
    evaluation = {'kind': 'artifact_study_hidden_evaluation', 'schema_version': 1,
        'generation_archive_id': args.generation_archive_id, 'image': image, 'outcome_ids': refs, 'summary': summary}
    identity = store.put_json(evaluation)
    checked = verify_hidden_evaluation(store, identity)
    (args.root / 'evaluation.json').write_bytes(canonical_json({'evaluation_id': identity, **checked}))
    print(json.dumps({'evaluation_id': identity, 'audit_complete': checked['audit_complete']}))
    return 0 if checked['audit_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
