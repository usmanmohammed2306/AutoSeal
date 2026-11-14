"""Trusted archive-only delivery entry point, with execution disabled.

The separate local research entry point retains its registered workflows.
This container has no worker, Docker socket, Sol credential or run endpoint.
"""

import json
import os
from pathlib import Path

from autoseal.api import create_app as core_app


class ArchiveOnly:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        path, method = scope['path'], scope['method']
        saved = (path in {'/api/health', '/api/access', '/api/cases', '/api/research/managed-repair',
                '/api/research/terminal-shell', '/api/research/sft-calibration'}
            or path.startswith(('/api/runs', '/api/workflows', '/api/research/native-swebench', '/api/research/training-pilots')))
        if method not in {'GET', 'HEAD'} or not saved:
            body = json.dumps({'detail': 'This delivery profile serves saved evidence only.'}).encode()
            await send({'type': 'http.response.start', 'status': 403,
                'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
            return await send({'type': 'http.response.body', 'body': body})
        if path == '/api/health':
            body = json.dumps({'status': 'ok', 'mode': 'archive-only', 'execution_enabled': False}).encode()
            await send({'type': 'http.response.start', 'status': 200,
                'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
            return await send({'type': 'http.response.body', 'body': b'' if method == 'HEAD' else body})
        return await self.app(scope, receive, send)


def create_app():
    database = os.environ['AUTOSEAL_DATABASE_URL']
    operator, reader = os.environ['AUTOSEAL_OPERATOR_TOKEN'], os.environ['AUTOSEAL_READER_TOKEN']
    if not operator or not reader or not database.startswith('postgresql+psycopg://'):
        raise ValueError('archive delivery requires PostgreSQL and separate operator/reader credentials')
    root = Path(os.environ.get('AUTOSEAL_DATA_ROOT', '/var/lib/autoseal'))
    def disabled(_candidate):
        raise RuntimeError('candidate execution is disabled in archive delivery')
    options = {}
    for prefix, root_key, id_key in [('MANAGED', 'managed_report_root', 'managed_report_identity'),
            ('SHELL', 'shell_archive_root', 'shell_archive_identity'), ('SFT', 'sft_archive_root', 'sft_evaluation_identity')]:
        directory, identity = os.environ.get('AUTOSEAL_' + prefix + '_ROOT'), os.environ.get('AUTOSEAL_' + prefix + '_ID')
        if directory or identity:
            if not directory or not identity:
                raise ValueError('archive location and immutable identity must be supplied together')
            options[root_key], options[id_key] = Path(directory), identity
    app = core_app(database, root / 'evidence', workflow_root=root / 'workflows', evaluator=disabled,
        operator_token=operator, reader_token=reader, **options)
    return ArchiveOnly(app)
