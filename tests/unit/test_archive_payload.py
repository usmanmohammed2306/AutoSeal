"""Payload graph selection never copies an entire research directory."""

import importlib.util
from pathlib import Path

import pytest

from autoseal.storage import ContentAddressedStore, IntegrityError


spec = importlib.util.spec_from_file_location('prepare_archive_payload',
    Path(__file__).resolve().parents[2] / 'scripts/prepare_archive_payload.py')
payload = importlib.util.module_from_spec(spec)
spec.loader.exec_module(payload)


def test_only_reachable_verified_objects_are_copied(tmp_path):
    source, target = (ContentAddressedStore(tmp_path / name) for name in ('source', 'target'))
    child = source.put_bytes(b'synthetic receipt')
    unrelated = source.put_bytes(b'private unrelated material must stay outside the payload')
    external = 'sha256:' + '0' * 64
    root = source.put_json({'child': child, 'external_model_fingerprint': external})
    budget = {'bytes': 0, 'objects': 0}
    result = payload.export_graph(source, target, root, budget)
    assert set(result['objects']) == {root, child}
    assert result['external_fingerprints'] == [external] and budget['objects'] == 2
    assert not target._path(unrelated).exists()
    assert target.get_json(root)['child'] == child


def test_corrupt_reachable_bytes_are_refused(tmp_path):
    source, target = (ContentAddressedStore(tmp_path / name) for name in ('source', 'target'))
    child = source.put_bytes(b'original synthetic receipt')
    root = source.put_json({'child': child})
    source._path(child).write_bytes(b'changed receipt')
    with pytest.raises(IntegrityError, match='digest'):
        payload.export_graph(source, target, root, {'bytes': 0, 'objects': 0})


def test_size_budget_refuses_payload_before_copying_object(tmp_path, monkeypatch):
    source, target = (ContentAddressedStore(tmp_path / name) for name in ('source', 'target'))
    root = source.put_bytes(b'too large for this synthetic budget')
    monkeypatch.setattr(payload, 'MAX_BYTES', 1)
    with pytest.raises(ValueError, match='budget'):
        payload.export_graph(source, target, root, {'bytes': 0, 'objects': 0})
    assert not target._path(root).exists()


def test_credential_shaped_bytes_require_review_without_copying(tmp_path):
    source, target = (ContentAddressedStore(tmp_path / name) for name in ('source', 'target'))
    root = source.put_bytes(b'AKIA' + b'A' * 16)
    with pytest.raises(ValueError, match='credential-shaped'):
        payload.export_graph(source, target, root, {'bytes': 0, 'objects': 0})
    assert not target._path(root).exists()


def test_absent_root_is_never_exported_as_a_completed_payload(tmp_path):
    source, target = (ContentAddressedStore(tmp_path / name) for name in ('source', 'target'))
    with pytest.raises(ValueError, match='root is missing'):
        payload.export_graph(source, target, 'sha256:' + '0' * 64, {'bytes': 0, 'objects': 0})
