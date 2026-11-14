"""Test the built Studio and API with disposable local credentials and state.

Checks gateway denial, server-side credential forwarding, reader behavior,
same-origin mutation and streamed body limits. Creates queue intent only; no
worker, Docker candidate, GPU job or public deployment is launched.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time

import httpx

from autoseal.storage import ContentAddressedStore


API = '''
import os,sys,uvicorn
from pathlib import Path
from autoseal.api import create_app
from autoseal.db import Base
app=create_app('sqlite:///'+sys.argv[1],Path(sys.argv[2]),operator_token=os.environ['AUTOSEAL_OPERATOR_TOKEN'],reader_token=os.environ['AUTOSEAL_READER_TOKEN'])
Base.metadata.create_all(app.state.run_service.sessions.kw['bind'])
uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[3]))
'''


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.root / 'evidence')
    operator, reader, password = [secrets.token_hex(32) for _ in range(3)]
    api_port, children, observations, checks = port(), [], [], {}
    base_env = dict(os.environ, AUTOSEAL_OPERATOR_TOKEN=operator, AUTOSEAL_READER_TOKEN=reader)
    status, error = 'FAILED', None
    started = datetime.now(timezone.utc).isoformat()
    clock = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='autoseal-studio-access-') as temporary, tempfile.TemporaryFile() as log:
        root = Path(temporary)
        def spawn(command, env):
            process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            children.append(process)
            return process
        def wait_for(url, process):
            for _ in range(150):
                try:
                    response = httpx.get(url, timeout=3)
                    if response.status_code in [200, 401, 503]:
                        return
                except httpx.TransportError:
                    pass
                if process.poll() is not None:
                    raise RuntimeError('validation server exited before readiness')
                time.sleep(.1)
            raise RuntimeError('validation server did not become ready')
        def request(client, method, path, expected, **kwargs):
            response = client.request(method, path, **kwargs)
            if any(secret in response.text for secret in [operator, reader, password]):
                raise RuntimeError('a server-side validation credential appeared in the response')
            observations.append(store.put_json({'method': method, 'path': path, 'status': response.status_code,
                'body': response.text, 'headers': {key: value for key, value in response.headers.items()
                    if key.lower() in {'content-type', 'cache-control', 'www-authenticate'}}}))
            if response.status_code != expected:
                raise RuntimeError(f'HTTP {response.status_code} at {path}; expected {expected}')
            return response
        try:
            api = spawn([sys.executable, '-c', API, str(root / 'state.db'), str(root / 'evidence'), str(api_port)], base_env)
            wait_for(f'http://127.0.0.1:{api_port}/api/health', api)
            for mode in ['operator', 'reader', 'missing_gateway']:
                studio_port = port()
                env = dict(base_env, AUTOSEAL_API_URL=f'http://127.0.0.1:{api_port}',
                    AUTOSEAL_API_TOKEN=reader if mode == 'reader' else operator,
                    AUTOSEAL_STUDIO_USER='local-validation', AUTOSEAL_STUDIO_PASSWORD=password,
                    AUTOSEAL_STUDIO_READ_ONLY='true' if mode == 'reader' else 'false',
                    AUTOSEAL_STUDIO_ORIGIN=f'http://127.0.0.1:{studio_port}')
                if mode == 'missing_gateway':
                    env.pop('AUTOSEAL_STUDIO_PASSWORD')
                studio = spawn(['pnpm', '--dir', 'apps/studio', 'start', '--port', str(studio_port)], env)
                wait_for(f'http://127.0.0.1:{studio_port}/workflows', studio)
                with httpx.Client(base_url=f'http://127.0.0.1:{studio_port}', timeout=20) as client:
                    request(client, 'GET', '/workflows', 503 if mode == 'missing_gateway' else 401)
                    if mode == 'missing_gateway':
                        checks['token_without_gateway_configuration_refused'] = True
                    else:
                        request(client, 'POST', '/api/workflows', 401, json={})
                        request(client, 'GET', '/api/workflows/00000000-0000-0000-0000-000000000000/stream', 401)
                        client.auth = ('local-validation', password)
                        page = request(client, 'GET', '/workflows', 200)
                        payload = {'kind': 'artifact_validate', 'payload': {'case': 'artifact-skip_hook-0'}, 'idempotency_key': secrets.token_hex(12)}
                        request(client, 'POST', '/api/workflows', 403, json=payload, headers={'Origin': 'https://untrusted.invalid'})
                        if mode == 'reader':
                            assert 'Validate repair' not in page.text
                            request(client, 'POST', '/api/workflows', 403, json=payload, headers={'Origin': env['AUTOSEAL_STUDIO_ORIGIN']})
                            stream = request(client, 'GET', '/api/workflows/' + workflow_id + '/stream', 200)
                            assert '"kind": "CANCELLED"' in stream.text
                            checks['authenticated_reader_sse_and_unauthenticated_denial'] = True
                            checks['reader_archive_access_and_mutation_denial'] = True
                        else:
                            row = request(client, 'POST', '/api/workflows', 202, json=payload, headers={'Origin': env['AUTOSEAL_STUDIO_ORIGIN']}).json()
                            workflow_id = row['id']
                            request(client, 'GET', '/workflows/' + row['id'], 200)
                            request(client, 'POST', '/api/workflows/' + row['id'] + '/cancel', 200, json={}, headers={'Origin': env['AUTOSEAL_STUDIO_ORIGIN']})
                            request(client, 'GET', '/api/workflows/' + row['id'] + '/stream', 400, headers={'Last-Event-ID': '-1'})
                            request(client, 'POST', '/api/workflows', 413, content=b'x' * 65537, headers={'Origin': env['AUTOSEAL_STUDIO_ORIGIN']})
                            checks['authenticated_browser_intent_and_cancel'] = True
                            checks['cross_origin_and_oversized_mutations_refused'] = True
                        checks['unauthenticated_pages_and_proxy_refused'] = True
                os.killpg(studio.pid, signal.SIGTERM)
                studio.wait(timeout=10)
            checks['no_response_exposes_validation_credentials'] = True
            status = 'PASSED'
        except Exception as exc:
            error = f'{type(exc).__name__}: {exc}'
            for secret in [operator, reader, password]:
                error = error.replace(secret, '[redacted]')
        finally:
            for child in children:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
            log.seek(0)
            contents = log.read().decode(errors='replace')
            for secret in [operator, reader, password]:
                contents = contents.replace(secret, '[redacted]')
            log_id = store.put_bytes(contents.encode())
    report = {'kind': 'local_built_studio_access_validation', 'schema_version': 1, 'status': status,
        'error': error, 'checks': checks, 'observations': observations, 'log_id': log_id,
        'started_at_utc': started, 'elapsed_seconds': time.monotonic() - clock,
        'sources': {str(p): store.put_bytes(p.read_bytes()) for p in [Path(__file__), *sorted(Path('apps/studio/app').rglob('*.tsx')),
            *sorted(Path('apps/studio/app/api').rglob('*.ts')), *sorted(Path('apps/studio/lib').glob('*.ts')),
            Path('apps/studio/proxy.ts'), Path('apps/studio/.next/BUILD_ID'), Path('src/autoseal/access.py'), Path('src/autoseal/api.py')]},
        'limitations': ['Real locally built Next.js and FastAPI servers with disposable credentials; no TLS/public deployment.',
            'Queue intent and cancellation only; candidate execution, PostgreSQL and GPU checks are separate.']}
    identity = store.put_json(report)
    (args.root / 'report.json').write_text(json.dumps({'report_id': identity}, indent=2) + '\n')
    print(json.dumps({'report_id': identity, 'status': status, 'checks': checks, 'error': error}, indent=2))
    return 0 if status == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
