"""Operational snapshot controls use inert bytes, not a database restore."""

import importlib.util
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('archive_snapshot', Path(__file__).resolve().parents[2] / 'scripts/archive_snapshot.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def example():
    raw = b'{"synthetic":true}'
    digest = snapshot.identity(raw)[7:]
    return {'database.dump': b'PGDMP-inert-unit-test', f'evidence/objects/{digest[:2]}/{digest}': raw}


def test_round_trip_preserves_bytes_and_protects_backup_permissions(tmp_path):
    files = example()
    root = tmp_path / 'backup'
    identity = snapshot.write_snapshot(root, files, source_images={'api': 'synthetic-unit-image'})
    manifest, restored = snapshot.read_snapshot(root, identity)
    assert restored == files and manifest['source_images']['api'] == 'synthetic-unit-image'
    assert root.stat().st_mode & 0o777 == 0o700
    assert all((root / name).stat().st_mode & 0o777 == 0o600 for name in files)


@pytest.mark.parametrize('change', ['manifest', 'payload', 'symlink', 'traversal', 'oversized'])
def test_corrupt_or_redirected_snapshot_is_refused_before_restore(tmp_path, change):
    root = tmp_path / 'backup'
    identity = snapshot.write_snapshot(root, example(), source_images={})
    if change == 'payload':
        (root / 'database.dump').write_bytes(b'PGDMP-corrupt-length!')
    elif change == 'symlink':
        (root / 'database.dump').unlink()
        (tmp_path / 'outside').write_bytes(b'PGDMP-inert-unit-test')
        (root / 'database.dump').symlink_to(tmp_path / 'outside')
    else:
        manifest = json.loads((root / 'manifest.json').read_bytes())
        if change == 'manifest':
            manifest['source_images']['api'] = 'different-image'
        elif change == 'traversal':
            manifest['files']['../../outside'] = {'identity': 'sha256:' + '0' * 64, 'bytes': 1}
        else:
            manifest['files']['database.dump']['bytes'] = snapshot.MAX_BYTES + 1
        raw = snapshot.canonical(manifest)
        (root / 'manifest.json').write_bytes(raw)
        if change != 'manifest':
            identity = snapshot.identity(raw)
    with pytest.raises(ValueError):
        snapshot.read_snapshot(root, identity)


def test_unrelated_files_and_incorrect_cas_paths_cannot_enter_backup(tmp_path):
    for name in ('.env', 'private.key', 'evidence/objects/ff/' + '0' * 64):
        with pytest.raises(ValueError):
            snapshot.write_snapshot(tmp_path / 'bad', {**example(), name: b'synthetic'}, source_images={})
    assert not (tmp_path / 'bad').exists()
