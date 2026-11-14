"""Validate the trusted archive containers on an isolated local Compose stack.

Uses disposable credentials, a new database/volume/network and loopback-only
Studio. Removes only this invocation's project. Never calls AWS or runs agents.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
import uuid

import httpx

from autoseal.storage import canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--https', action='store_true', help='Also verify local TLS using an isolated private CA.')
    parser.add_argument('--recovery', action='store_true', help='Back up an actual Docker fixture receipt and restore PostgreSQL/CAS into a separate local stack.')
    parser.add_argument('--rollback-image', help='With --recovery, check a distinct reviewed local API image by immutable sha256 identity.')
    parser.add_argument('--image-inventory', type=Path, help='With --https, check a local immutable Linux/amd64 image inventory instead of the default images.')
    parser.add_argument('--model-payload', type=Path, help='Mount an explicitly prepared private model-evidence payload read-only.')
    parser.add_argument('--payload-id', help='Reviewed SHA-256 identity of that payload manifest.')
    args = parser.parse_args()
    if args.rollback_image and not args.recovery:
        parser.error('--rollback-image requires --recovery')
    if args.image_inventory and not args.https:
        parser.error('--image-inventory requires --https')
    if bool(args.model_payload) != bool(args.payload_id):
        parser.error('--model-payload and --payload-id must be supplied together')
    args.root.mkdir(parents=True, exist_ok=False)
    project = 'autoseal_archive_' + uuid.uuid4().hex[:12]
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    env = {**os.environ, 'AUTOSEAL_DB_PASSWORD': secrets.token_hex(24), 'AUTOSEAL_OPERATOR_TOKEN': secrets.token_hex(32),
        'AUTOSEAL_READER_TOKEN': secrets.token_hex(32), 'AUTOSEAL_STUDIO_USER': 'local-reviewer',
        'AUTOSEAL_STUDIO_PASSWORD': secrets.token_hex(24), 'AUTOSEAL_STUDIO_PORT': str(port)}
    compose = ['docker', 'compose', '-p', project, '-f', 'deploy/compose.archive.yaml']
    if args.https:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); tls_port = sock.getsockname()[1]
        env['AUTOSEAL_TLS_PORT'] = str(tls_port)
        compose += ['-f', 'deploy/compose.tls-local.yaml']
    report = {'kind': 'archive_delivery_validation', 'schema_version': 1, 'status': 'FAILED', 'checks': [],
        'source_files': {}, 'limitations': ['Isolated Mac Docker validation, not public HTTPS or operated AWS.',
            'Empty-state/authentication/container/migration checks; no reviewed evidence import or live execution bridge.',
            'Disposable credentials are omitted. No backup/restore, load or cloud cost result is inferred.']}
    def command(argv, *, input=None, timeout=60, check=True):
        result = subprocess.run(argv, input=input, env=env, capture_output=True, timeout=timeout)
        if check and result.returncode:
            # Compose stderr normally contains service names, not environment
            # values. Never persist arbitrary output without removing secrets.
            detail = result.stderr.decode(errors='replace')[-2000:]
            for key in ('AUTOSEAL_DB_PASSWORD', 'AUTOSEAL_READER_TOKEN', 'AUTOSEAL_OPERATOR_TOKEN', 'AUTOSEAL_STUDIO_PASSWORD'):
                detail = detail.replace(env[key], '[REDACTED]')
            raise RuntimeError(f'local container command exited {result.returncode}: {detail}')
        return result
    def passed(name, condition):
        if not condition:
            raise AssertionError(name)
        report['checks'].append({'name': name, 'passed': True})
    def api(path, *, token=None, method='GET'):
        payload = json.dumps({'path': path, 'method': method, 'token': token}).encode()
        code = '''import json,sys,urllib.request,urllib.error
q=json.load(sys.stdin);headers={'Authorization':'Bearer '+q['token']} if q['token'] else {}
r=urllib.request.Request('http://127.0.0.1:8000'+q['path'],method=q['method'],headers=headers)
try:
 with urllib.request.urlopen(r,timeout=45 if q['path'] in {'/api/research/model-study','/api/research/sft-calibration'} else 5) as p:
  raw=p.read(2*1024*1024+1); assert len(raw)<=2*1024*1024
  print(json.dumps({'status':p.status,'body':raw.decode()}))
except urllib.error.HTTPError as p:print(json.dumps({'status':p.code,'body':p.read(4096).decode()}))
'''
        return json.loads(command(compose + ['exec', '-T', 'api', 'python', '-c', code], input=payload).stdout)
    started = time.monotonic()
    try:
        paths = [Path('deploy/api.Dockerfile'), Path('deploy/studio.Dockerfile'), Path('deploy/archive_api.py'),
            Path('deploy/requirements.server.lock'), Path('deploy/compose.archive.yaml'), Path('apps/studio/pnpm-lock.yaml'), Path(__file__)]
        report['source_files'] = {str(path): 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        if args.https:
            for path in map(Path, ['deploy/caddy.Dockerfile', 'deploy/Caddyfile.local', 'deploy/compose.tls-local.yaml']):
                report['source_files'][str(path)] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
        if args.image_inventory:
            inventory = json.loads(args.image_inventory.read_bytes())
            if set(inventory) != {'platform', 'api', 'studio', 'proxy'} or inventory['platform'] != 'linux/amd64':
                raise ValueError('expected a Linux/amd64 API, Studio and proxy inventory')
            for name in ('api', 'studio', 'proxy'):
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', inventory[name]):
                    raise ValueError('image inventory requires immutable local identities')
                inspected = json.loads(command(['docker', 'image', 'inspect', inventory[name]]).stdout)[0]
                if (inspected['Os'], inspected['Architecture']) != ('linux', 'amd64'):
                    raise ValueError('local image does not match the declared Linux/amd64 platform')
            overrides = {name: {'image': inventory['api' if name == 'migrate' else name], 'platform': inventory['platform']}
                for name in ('api', 'migrate', 'studio', 'proxy')}
            overrides['db'] = {'platform': inventory['platform']}
            override = args.root.resolve() / 'local-image-inventory.json'
            override.write_text(json.dumps({'services': overrides}))
            compose += ['-f', str(override)]
            report['image_inventory'] = inventory
            report['limitations'].append('Linux/amd64 runs under local Mac Docker emulation; this is not native cloud performance.')
        if args.model_payload:
            raw = (args.model_payload / 'manifest.json').read_bytes()
            if 'sha256:' + hashlib.sha256(raw).hexdigest() != args.payload_id:
                raise ValueError('model payload differs from the reviewed manifest identity')
            payload = json.loads(raw)
            if (payload['kind'] != 'autoseal_private_archive_payload' or payload['schema_version'] != 1
                    or set(payload['packs']) != {'study', 'sft'}):
                raise ValueError('unsupported private model-evidence payload')
            for name in ('study', 'sft'):
                if not re.fullmatch(r'sha256:[0-9a-f]{64}', payload['packs'][name]['root_identity']):
                    raise ValueError('model evidence requires pinned evaluation identities')
            override = args.root.resolve() / 'local-model-payload.json'
            override.write_text(json.dumps({'services': {'api': {
                'volumes': [{'type': 'bind', 'source': str(args.model_payload.resolve()), 'target': '/srv/model-evidence', 'read_only': True}],
                'environment': {'AUTOSEAL_STUDY_ROOT': '/srv/model-evidence/study',
                    'AUTOSEAL_STUDY_ID': payload['packs']['study']['root_identity'],
                    'AUTOSEAL_SFT_ROOT': '/srv/model-evidence/sft',
                    'AUTOSEAL_SFT_ID': payload['packs']['sft']['root_identity']}}}}))
            compose += ['-f', str(override)]
            report['model_payload_id'] = args.payload_id
        command(compose + ['up', '-d', '--no-build'], timeout=120)
        deadline = time.monotonic() + 60
        while True:
            try:
                if api('/api/health')['status'] == 200:
                    break
            except (RuntimeError, json.JSONDecodeError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError('private API did not become ready')
            time.sleep(.5)
        with httpx.Client(base_url=f'http://127.0.0.1:{port}', timeout=10) as client:
            deadline = time.monotonic() + 60
            while True:
                try:
                    if client.get('/').status_code == 401:
                        break
                except httpx.HTTPError:
                    pass
                if time.monotonic() > deadline:
                    raise RuntimeError('Studio did not become ready')
                time.sleep(.5)
            passed('unauthenticated_studio_denied', client.get('/training').status_code == 401)
            credentials = base64.b64encode((env['AUTOSEAL_STUDIO_USER'] + ':' + env['AUTOSEAL_STUDIO_PASSWORD']).encode()).decode()
            headers = {'Authorization': 'Basic ' + credentials}
            page = client.get('/', headers=headers)
            passed('authenticated_studio_reads_real_empty_database', page.status_code == 200 and 'AutoSeal' in page.text)
            denied = client.post('/api/workflows', headers={**headers, 'Origin': f'http://127.0.0.1:{port}'}, json={})
            passed('studio_cannot_start_work', denied.status_code == 403)
            passed('api_secret_absent_from_html', not any(value in page.text for key, value in env.items()
                if key in {'AUTOSEAL_READER_TOKEN', 'AUTOSEAL_OPERATOR_TOKEN', 'AUTOSEAL_DB_PASSWORD'}))
        passed('private_api_requires_authentication', api('/api/runs')['status'] == 401)
        saved = api('/api/runs', token=env['AUTOSEAL_READER_TOKEN'])
        passed('migrated_postgres_returns_empty_saved_runs', saved['status'] == 200 and json.loads(saved['body']) == [])
        health = api('/api/health')
        passed('health_declares_execution_disabled', json.loads(health['body'])['execution_enabled'] is False)
        passed('operator_also_cannot_submit', api('/api/runs', token=env['AUTOSEAL_OPERATOR_TOKEN'], method='POST')['status'] == 403)
        passed('legacy_research_get_cannot_execute', api('/api/research/fixtures/exploit/influence', token=env['AUTOSEAL_OPERATOR_TOKEN'])['status'] == 403)
        containers = command(compose + ['ps', '-q', 'api', 'studio']).stdout.decode().split()
        inspections = json.loads(command(['docker', 'inspect', *containers]).stdout)
        report['images'] = {row['Config']['Labels']['com.docker.compose.service']: row['Image'] for row in inspections}
        passed('services_nonroot_readonly_and_no_docker_socket', len(inspections) == 2 and all(
            row['Config']['User'] not in {'', '0', '0:0', 'root'} and row['HostConfig']['ReadonlyRootfs']
            and row['HostConfig']['CapDrop'] == ['ALL'] and all('docker.sock' not in item['Destination'] for item in row['Mounts'])
            for row in inspections))
        passed('only_loopback_studio_listener', all(binding['HostIp'] == '127.0.0.1'
            for row in inspections for bindings in row['NetworkSettings']['Ports'].values() for binding in bindings or []))
        isolation = command(compose + ['exec', '-T', 'api', 'python', '-c',
            "from pathlib import Path; import shutil; assert not any((Path('/app')/p).exists() for p in ['research','.git','.env','AGENTS.md']); assert shutil.which('docker') is None; print('isolated')"])
        passed('private_planning_and_docker_cli_absent', isolation.stdout.strip() == b'isolated')
        runtime_paths = sorted([*Path('src/autoseal').glob('*.py'), *Path('migrations').rglob('*.py'), Path('deploy/archive_api.py')])
        expected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in runtime_paths}
        code = "import hashlib,json,sys; from pathlib import Path; names=json.load(sys.stdin); print(json.dumps({name:hashlib.sha256((Path('/app')/name).read_bytes()).hexdigest() for name in names}))"
        observed = json.loads(command(compose + ['exec', '-T', 'api', 'python', '-c', code], input=json.dumps(list(expected)).encode()).stdout)
        passed('api_runtime_sources_match_checkout', observed == expected)
        report['runtime_source_files'] = expected
        studio = Path('apps/studio')
        frontend_paths = sorted([*(studio / 'app').rglob('*.tsx'), *(studio / 'app').rglob('*.ts'),
            *(studio / 'app').rglob('*.css'), *(studio / 'lib').rglob('*.ts'),
            *(studio / name for name in ['package.json', 'pnpm-lock.yaml', 'proxy.ts', 'next.config.ts', 'tsconfig.json'])])
        frontend = {str(path.relative_to(studio)): hashlib.sha256(path.read_bytes()).hexdigest() for path in frontend_paths}
        code = "const fs=require('fs'),crypto=require('crypto'); const names=JSON.parse(fs.readFileSync(0,'utf8')); console.log(JSON.stringify(Object.fromEntries(names.map(name=>[name,crypto.createHash('sha256').update(fs.readFileSync('/app/reference-source/'+name)).digest('hex')]))))"
        observed = json.loads(command(compose + ['exec', '-T', 'studio', 'node', '-e', code], input=json.dumps(list(frontend)).encode()).stdout)
        passed('studio_build_source_snapshot_matches_checkout', observed == frontend)
        report['frontend_source_files'] = frontend
        if args.https:
            deadline = time.monotonic() + 45
            while True:
                ca = command(compose + ['exec', '-T', 'proxy', 'cat', '/data/caddy/pki/authorities/local/root.crt'], check=False)
                if ca.returncode == 0:
                    break
                if time.monotonic() > deadline:
                    raise RuntimeError('local TLS authority did not become ready')
                time.sleep(.5)
            ca_file = args.root / 'local-test-ca.pem'; ca_file.write_bytes(ca.stdout)
            context = ssl.create_default_context(cafile=str(ca_file))
            with httpx.Client(base_url=f'https://127.0.0.1:{tls_port}', verify=context, timeout=10) as client:
                denied = client.get('/training')
                passed('verified_local_tls_requires_login', denied.status_code == 401)
                page = client.get('/', headers=headers)
                passed('verified_local_tls_serves_studio', page.status_code == 200 and 'AutoSeal' in page.text)
                passed('tls_response_disables_content_sniffing_and_caching', page.headers.get('x-content-type-options') == 'nosniff'
                    and page.headers.get('cache-control') == 'no-store')
            proxy_id = command(compose + ['ps', '-q', 'proxy']).stdout.decode().strip()
            proxy = json.loads(command(['docker', 'inspect', proxy_id]).stdout)[0]
            report['images']['proxy'] = proxy['Image']
            passed('tls_proxy_is_nonroot_without_capabilities', proxy['Config']['User'] == '10001:10001'
                and proxy['HostConfig']['CapDrop'] == ['ALL'] and proxy['HostConfig']['ReadonlyRootfs'])
            report['limitations'].append('Local TLS uses only an isolated test CA trusted by this client, not the host trust store or a public CA.')
        if args.model_payload:
            for kind, path, identity_key in [('study', '/api/research/model-study', 'evaluation_id'),
                    ('sft', '/api/research/sft-calibration', 'evaluation_id')]:
                started_view = time.monotonic()
                response = api(path, token=env['AUTOSEAL_READER_TOKEN'])
                value = json.loads(response['body'])
                passed(f'private_{kind}_payload_reverified_inside_container', response['status'] == 200
                    and value[identity_key] == payload['packs'][kind]['root_identity'])
                report.setdefault('saved_view_seconds', {})[kind] = time.monotonic() - started_view
            # Read the actual Studio stream. The checking state must arrive
            # before the completed receipt table; no fake progress is inferred.
            started_view = time.monotonic()
            chunks, received, shell_seconds = [], 0, None
            with httpx.Client(timeout=60) as viewer:
                with viewer.stream('GET', f'http://127.0.0.1:{port}/training', headers=headers) as response:
                    if response.status_code != 200:
                        raise RuntimeError(f'training page returned HTTP {response.status_code}')
                    for chunk in response.iter_bytes():
                        received += len(chunk)
                        if received > 4 * 1024 * 1024:
                            raise RuntimeError('training page exceeded its review byte budget')
                        chunks.append(chunk)
                        if shell_seconds is None and b'Checking the saved model comparison.' in b''.join(chunks):
                            shell_seconds = time.monotonic() - started_view
            page = b''.join(chunks).decode()
            complete_seconds = time.monotonic() - started_view
            passed('studio_streams_checking_state_before_verified_model_table', shell_seconds is not None
                and shell_seconds < complete_seconds
                and page.index('Checking the saved model comparison.') < page.index('Compare what the models actually submitted.'))
            passed('model_page_omits_application_credentials', not any(env[key] in page for key in (
                'AUTOSEAL_DB_PASSWORD', 'AUTOSEAL_READER_TOKEN', 'AUTOSEAL_OPERATOR_TOKEN', 'AUTOSEAL_STUDIO_PASSWORD')))
            report['saved_view_seconds'].update(training_checking_state_bytes=shell_seconds, training_complete_stream=complete_seconds)
            report['limitations'] = [item for item in report['limitations'] if not item.startswith('Empty-state/')]
            report['limitations'].append('The PostgreSQL run list begins empty; the separate private model-evidence mount is reverified independently. No live execution bridge is enabled.')
            report['limitations'].append('Private reviewed model evidence is mounted read-only; no model inference, optimizer deserialization or candidate execution takes place in this application profile.')
        if args.recovery:
            from archive_recovery import validate_recovery
            for path in map(Path, ['scripts/archive_recovery.py', 'scripts/archive_snapshot.py']):
                report['source_files'][str(path)] = 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()
            validate_recovery(compose=compose, command=command,
                api=lambda path: api(path, token=env['AUTOSEAL_READER_TOKEN']), passed=passed, root=args.root,
                report=report, rollback_image=args.rollback_image)
            report['limitations'] = [item for item in report['limitations']
                if not item.startswith(('Empty-state/', 'Disposable credentials'))]
            report['limitations'].append('One imported reviewed fixture and a quiescent local database/CAS restore; no operated AWS, model archive import, production RPO/RTO or load guarantee. Credentials are omitted.')
        report['status'] = 'PASSED'
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        logs = command(compose + ['logs', '--no-color', '--tail=35'], check=False).stdout.decode(errors='replace')
        for key in ('AUTOSEAL_DB_PASSWORD', 'AUTOSEAL_READER_TOKEN', 'AUTOSEAL_OPERATOR_TOKEN', 'AUTOSEAL_STUDIO_PASSWORD'):
            logs = logs.replace(env[key], '[REDACTED]')
        (args.root / 'failure-logs.txt').write_text(logs)
    finally:
        cleanup = command(compose + ['down', '--volumes', '--remove-orphans'], check=False)
        report['cleanup_succeeded'] = cleanup.returncode == 0
        if cleanup.returncode:
            report['status'] = 'FAILED'
        report['seconds'] = time.monotonic() - started
        raw = canonical_json(report)
        (args.root / 'report.json').write_bytes(raw)
        print(json.dumps({'status': report['status'], 'checks': len(report['checks']),
            'cleanup_succeeded': report['cleanup_succeeded'], 'report_id': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'error': report.get('error')}))
    return 0 if report['status'] == 'PASSED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
