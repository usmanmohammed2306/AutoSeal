"""Prepare verified local model evidence for a later reviewed private upload.

Copies only reachable content objects, never planning directories or an entire
working tree. Nothing is uploaded. Optimizer files remain inert bytes. The
target container independently rechecks the original evaluation identities.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from autoseal.artifact_study_review import study_review
from autoseal.sft_archive import calibration_view
from autoseal.storage import ContentAddressedStore, canonical_json


DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
FORBIDDEN = [re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----'),
    re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')]
MAX_BYTES = 512 * 1024 * 1024
MAX_OBJECTS = 8192


def references(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str) and DIGEST.fullmatch(item):
            yield item


def export_graph(source, target, root_identity, budget):
    pending, seen, external = [root_identity], {}, set()
    while pending:
        ref = pending.pop()
        if ref in seen or ref in external:
            continue
        # Some SHA-256 values are external provenance fingerprints rather
        # than CAS references. Destination receipt verification distinguishes
        # these from any required missing evidence object.
        if not source._path(ref).exists():
            external.add(ref)
            continue
        raw = source.get_bytes(ref)
        if any(pattern.search(raw) for pattern in FORBIDDEN):
            raise ValueError('credential-shaped bytes require a separate evidence review; nothing may be uploaded')
        budget['bytes'] += len(raw); budget['objects'] += 1
        if budget['bytes'] > MAX_BYTES or budget['objects'] > MAX_OBJECTS:
            raise ValueError('published-evidence payload exceeds its review budget')
        if target.put_bytes(raw) != ref:
            raise ValueError('copied evidence identity changed')
        seen[ref] = len(raw)
        if len(raw) <= 4 * 1024 * 1024 and raw[:1] in {b'{', b'['}:
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                continue
            pending.extend(references(value))
    if root_identity not in seen:
        raise ValueError('payload root is missing')
    return {'root_identity': root_identity, 'objects': seen, 'external_fingerprints': sorted(external)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study-root', type=Path, required=True)
    parser.add_argument('--study-evaluation-id', required=True)
    parser.add_argument('--sft-root', type=Path, required=True)
    parser.add_argument('--sft-evaluation-id', required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    study_review(args.study_root, args.study_evaluation_id)
    calibration_view(ContentAddressedStore(args.sft_root / 'evidence'), args.sft_evaluation_id)
    args.root.mkdir(parents=True, exist_ok=False, mode=0o700)
    budget = {'bytes': 0, 'objects': 0}
    packs = {}
    for name, directory, ref in [('study', args.study_root, args.study_evaluation_id),
            ('sft', args.sft_root, args.sft_evaluation_id)]:
        packs[name] = export_graph(ContentAddressedStore(directory / 'evidence'),
            ContentAddressedStore(args.root / name / 'evidence'), ref, budget)
    # Verify the exported graph, not just the source summaries or file hashes.
    study_review(args.root / 'study', args.study_evaluation_id)
    calibration_view(ContentAddressedStore(args.root / 'sft/evidence'), args.sft_evaluation_id)
    manifest = {'kind': 'autoseal_private_archive_payload', 'schema_version': 1, 'packs': packs,
        'totals': budget, 'scope': 'Original frozen SFT and finite-task model comparison; no new inference, training or efficacy claim.',
        'review': 'Reachable CAS only. Two credential-shaped byte checks are not a universal secret scan. Original machine paths may remain in protected receipts. No public object-download route is added.'}
    raw = canonical_json(manifest)
    (args.root / 'manifest.json').write_bytes(raw)
    identity = 'sha256:' + hashlib.sha256(raw).hexdigest()
    (args.root / 'identity.json').write_bytes(canonical_json({'payload_id': identity}))
    print(json.dumps({'payload_id': identity, **budget}))


if __name__ == '__main__':
    main()
