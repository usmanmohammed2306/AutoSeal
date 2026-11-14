"""Archive delivery cannot accidentally start a research GET or mutation."""

import asyncio
import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location('autoseal_archive_delivery', Path(__file__).resolve().parents[2] / 'deploy/archive_api.py')
delivery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delivery)


@pytest.mark.parametrize('path,method', [('/api/runs', 'POST'), ('/api/workflows', 'POST'),
    ('/api/research/fixtures/exploit/influence', 'GET'), ('/api/research/promotion-review', 'GET'), ('/docs', 'GET')])
def test_archive_boundary_refuses_execution_before_calling_the_core(path, method):
    async def core(*_args):
        raise AssertionError('a denied archive request reached core research execution')
    sent = []
    async def send(message):
        sent.append(message)
    asyncio.run(delivery.ArchiveOnly(core)({'type': 'http', 'path': path, 'method': method}, None, send))
    assert sent[0]['status'] == 403


def test_saved_evidence_still_reaches_core_authentication():
    called = []
    async def core(scope, _receive, _send):
        called.append(scope['path'])
    asyncio.run(delivery.ArchiveOnly(core)({'type': 'http', 'path': '/api/runs', 'method': 'GET'}, None, None))
    assert called == ['/api/runs']


def test_health_names_archive_mode_without_execution():
    async def core(*_args):
        raise AssertionError('health reached a research handler')
    sent = []
    async def send(message):
        sent.append(message)
    asyncio.run(delivery.ArchiveOnly(core)({'type': 'http', 'path': '/api/health', 'method': 'GET'}, None, send))
    assert sent[0]['status'] == 200 and b'"execution_enabled": false' in sent[1]['body']
