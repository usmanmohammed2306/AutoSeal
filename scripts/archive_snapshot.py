"""Bounded, digest-checked snapshots for the trusted read-only delivery profile.

This is an internal operational helper. It never reads environment files,
extracts a tar archive, launches candidates or deserializes model checkpoints.
The caller supplies the expected manifest identity from its retained report.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re


MAX_FILES = 4096
MAX_BYTES = 128 * 1024 * 1024
CAS_NAME = re.compile(r'evidence/objects/([0-9a-f]{2})/([0-9a-f]{64})\Z')


def identity(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_names(files):
    if not files or len(files) > MAX_FILES or 'database.dump' not in files:
        raise ValueError('snapshot needs a database and a bounded file inventory')
    total = 0
    for name, raw in files.items():
        path = PurePosixPath(name)
        if path.is_absolute() or str(path) != name or any(part in {'.', '..'} for part in path.parts):
            raise ValueError('snapshot path is not canonical')
        if not isinstance(raw, bytes):
            raise ValueError('snapshot payload must be bytes')
        if name != 'database.dump':
            match = CAS_NAME.fullmatch(name)
            if not match or match[1] != match[2][:2] or identity(raw) != 'sha256:' + match[2]:
                raise ValueError('snapshot evidence path does not match its content')
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError('snapshot exceeds the retained-byte budget')
    if not files['database.dump'].startswith(b'PGDMP'):
        raise ValueError('snapshot database must be a PostgreSQL custom-format dump')


def write_snapshot(root, files, *, source_images):
    validate_names(files)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, raw in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o600)
    manifest = {'kind': 'autoseal_archive_snapshot', 'schema_version': 1,
        'consistency': 'Quiescent read-only profile with no worker or external writer',
        'source_images': source_images,
        'files': {name: {'identity': identity(raw), 'bytes': len(raw)} for name, raw in sorted(files.items())}}
    raw = canonical(manifest)
    (root / 'manifest.json').write_bytes(raw)
    (root / 'manifest.json').chmod(0o600)
    return identity(raw)


def read_snapshot(root, expected_identity):
    root = Path(root)
    if root.is_symlink() or (root / 'manifest.json').is_symlink():
        raise ValueError('snapshot symlinks are refused')
    if (root / 'manifest.json').stat().st_size > 2 * 1024 * 1024:
        raise ValueError('snapshot manifest exceeds its budget')
    raw = (root / 'manifest.json').read_bytes()
    if identity(raw) != expected_identity:
        raise ValueError('snapshot manifest identity differs from the retained report')
    manifest = json.loads(raw)
    if manifest.get('kind') != 'autoseal_archive_snapshot' or manifest.get('schema_version') != 1:
        raise ValueError('unsupported archive snapshot')
    records = manifest['files']
    if not isinstance(records, dict) or not 1 <= len(records) <= MAX_FILES:
        raise ValueError('snapshot file inventory exceeds its budget')
    # Validate every name and declared size before touching any payload path.
    total = 0
    for name, record in records.items():
        if name != 'database.dump':
            match = CAS_NAME.fullmatch(name)
            if not match or match[1] != match[2][:2]:
                raise ValueError('snapshot inventory contains an unapproved path')
        if type(record['bytes']) is not int or record['bytes'] < 0:
            raise ValueError('snapshot byte length is invalid')
        total += record['bytes']
        if total > MAX_BYTES:
            raise ValueError('snapshot exceeds the retained-byte budget')
    files = {}
    for name, record in records.items():
        target = root / name
        if any(part.is_symlink() for part in (target, *target.parents)):
            raise ValueError('snapshot symlinks are refused')
        if target.stat().st_size != record['bytes']:
            raise ValueError('snapshot payload length mismatch')
        content = target.read_bytes()
        if identity(content) != record['identity']:
            raise ValueError('snapshot payload digest mismatch')
        files[name] = content
    validate_names(files)
    return manifest, files
