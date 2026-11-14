"""Scoped recovery checks called by validate_archive_delivery.py on Mac Docker."""

import base64
import json
from pathlib import Path
import re
import time

from archive_snapshot import identity, read_snapshot, write_snapshot


def validate_recovery(*, compose, command, api, passed, root, report, rollback_image=None):
    # A different Compose project creates independent PostgreSQL and CAS volumes.
    target = list(compose)
    target[3] += '_restore'
    recovery = {'scope': 'Quiescent local archive profile; no AWS recovery guarantee',
        'source_read_only': True, 'restored_project_cleanup': False}
    report['recovery'] = recovery
    api_code = '''import json,os,sys,urllib.request
q=json.load(sys.stdin); r=urllib.request.Request('http://127.0.0.1:8000'+q['path'],headers={'Authorization':'Bearer '+os.environ['AUTOSEAL_READER_TOKEN']})
with urllib.request.urlopen(r,timeout=5) as p:
 raw=p.read(2*1024*1024+1); assert len(raw)<=2*1024*1024
 print(json.dumps({'status':p.status,'body':json.loads(raw)}))
'''
    def target_api(path):
        return json.loads(command(target + ['exec', '-T', 'api', 'python', '-c', api_code],
            input=json.dumps({'path': path}).encode()).stdout)
    def ready():
        deadline = time.monotonic() + 60
        while True:
            try:
                if target_api('/api/runs')['status'] == 200:
                    return
            except (RuntimeError, json.JSONDecodeError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError('restored API did not become ready')
            time.sleep(.5)

    try:
        from autoseal.service import docker_compare
        # Compare the serialized evidence contract: Python command tuples cross
        # the JSON API as arrays without changing the recorded command bytes.
        pair = json.loads(json.dumps(docker_compare('exploit')))
        (Path(root) / 'recovery-control.json').write_text(json.dumps(pair, sort_keys=True))
        passed('recovery_input_is_actual_docker_false_reward', pair['classification'] == 'FALSE_REWARD'
            and pair['proxy']['candidate_identity'] == pair['audit']['candidate_identity'])
        # This trusted management process imports an already evaluated fixture.
        # It does not enable the web mutation boundary or run a worker in AWS.
        import_code = '''import json,os,sys
from pathlib import Path
from autoseal.db import make_session_factory
from autoseal.service import RunService
from autoseal.storage import ContentAddressedStore
pair=json.load(sys.stdin)
service=RunService(make_session_factory(os.environ['AUTOSEAL_DATABASE_URL']),ContentAddressedStore(Path('/var/lib/autoseal/evidence')),evaluator=lambda _:pair)
row=service.submit('exploit','local-recovery-control');done=service.process_one()
assert done.id==row.id and done.state=='COMPLETED'
print(json.dumps({'run_id':done.id,'manifest_id':done.manifest_id}))
'''
        imported = json.loads(command(compose + ['exec', '-T', 'api', 'python', '-c', import_code],
            input=json.dumps(pair).encode()).stdout)
        recovery.update(run_id=imported['run_id'], evidence_id=imported['manifest_id'])
        run_path = '/api/runs/' + imported['run_id']
        before = {}
        for suffix in ('', '/evidence', '/events'):
            response = api(run_path + suffix)
            if response['status'] != 200:
                raise RuntimeError(f"source archive HTTP {response['status']} for retained {suffix or 'run'}")
            before[suffix] = json.loads(response['body'])
        (Path(root) / 'recovery-before.json').write_text(json.dumps(before, sort_keys=True))
        passed('readonly_archive_reads_imported_docker_receipt', before['/evidence'] == pair
            and before['']['manifest_id'] == imported['manifest_id'])
        started = time.monotonic()
        dump = command(compose + ['exec', '-T', 'db', 'pg_dump', '-U', 'autoseal', '-d', 'autoseal',
            '--format=custom', '--no-owner', '--no-acl']).stdout
        export_code = '''import base64,json
from pathlib import Path
from autoseal.storage import ContentAddressedStore
root=Path('/var/lib/autoseal'); store=ContentAddressedStore(root/'evidence'); result={}; total=0
for p in sorted((root/'evidence/objects').glob('*/*')):
 assert p.is_file() and not p.is_symlink()
 raw=store.get_bytes('sha256:'+p.name);total+=len(raw)
 assert len(result)<4095 and total<=128*1024*1024
 result[str(p.relative_to(root))]=base64.b64encode(raw).decode()
print(json.dumps(result))
'''
        encoded = json.loads(command(compose + ['exec', '-T', 'api', 'python', '-c', export_code]).stdout)
        files = {'database.dump': dump, **{name: base64.b64decode(raw, validate=True) for name, raw in encoded.items()}}
        backup = Path(root) / 'snapshot'
        snapshot_id = write_snapshot(backup, files, source_images=report['images'])
        manifest, verified = read_snapshot(backup, snapshot_id)
        recovery.update(snapshot_id=snapshot_id, payload_files=len(files),
            payload_bytes=sum(len(raw) for raw in files.values()), backup_seconds=time.monotonic()-started,
            run_id=imported['run_id'], evidence_id=imported['manifest_id'])
        passed('database_and_cas_snapshot_reverified', verified == files and len(files) > 1)
        # A corrupt copy must fail before any restore command is attempted.
        corrupted = {**files, 'database.dump': files['database.dump'][:-1] + bytes([files['database.dump'][-1] ^ 1])}
        bad = Path(root) / 'corrupt-snapshot'
        write_snapshot(bad, files, source_images=report['images'])
        (bad / 'database.dump').write_bytes(corrupted['database.dump'])
        rejected = False
        try:
            read_snapshot(bad, snapshot_id)
        except ValueError:
            rejected = True
        passed('corrupt_snapshot_refused_before_database_restore', rejected)

        started = time.monotonic()
        command(target + ['up', '-d', '--no-build', 'db'], timeout=120)
        deadline = time.monotonic() + 45
        # The entrypoint briefly runs a socket-only initialization server.
        # TCP readiness avoids restoring into that server as it shuts down.
        while command(target + ['exec', '-T', 'db', 'pg_isready', '-h', '127.0.0.1', '-U', 'autoseal', '-d', 'autoseal'], check=False).returncode:
            if time.monotonic() > deadline:
                raise RuntimeError('fresh restore database did not become ready')
            time.sleep(.5)
        command(target + ['exec', '-T', 'db', 'pg_restore', '-h', '127.0.0.1', '-U', 'autoseal', '-d', 'autoseal',
            '--exit-on-error', '--no-owner', '--no-acl'], input=verified['database.dump'])
        passed('postgres_dump_restored_into_separate_fresh_volume', True)
        restore_code = '''import base64,json,sys
from pathlib import Path
from autoseal.storage import ContentAddressedStore
store=ContentAddressedStore(Path('/var/lib/autoseal/evidence')); result={}
for name,text in json.load(sys.stdin).items():
 raw=base64.b64decode(text,validate=True);ref=store.put_bytes(raw)
 assert name=='evidence/objects/'+ref[7:9]+'/'+ref[7:]
 assert store.get_bytes(ref)==raw
 result[name]=ref
print(json.dumps(result))
'''
        restored = json.loads(command(target + ['run', '--rm', '--no-deps', '-T', 'api', 'python', '-c', restore_code],
            input=json.dumps(encoded).encode()).stdout)
        passed('cas_restored_with_original_content_identities', restored == {name: identity(files[name]) for name in encoded})
        command(target + ['up', '-d', '--no-build', 'api'], timeout=120)
        ready()
        after = {suffix: target_api(run_path + suffix)['body'] for suffix in before}
        passed('restored_api_matches_run_evidence_and_event_history', after == before)
        recovery['restore_seconds'] = time.monotonic() - started

        if rollback_image is not None:
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', rollback_image):
                raise ValueError('rollback image must be an already reviewed local immutable image identity')
            command(['docker', 'image', 'inspect', rollback_image])
            current = report['images']['api']
            if rollback_image == current:
                raise ValueError('rollback must exercise a distinct previous application image')
            for label, image in [('previous', rollback_image), ('current', current)]:
                override = Path(root).resolve() / f'{label}-image.json'
                override.write_text(json.dumps({'services': {'api': {'image': image}}}))
                command(target + ['-f', str(override), 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'api'], timeout=120)
                ready()
                container = command(target + ['ps', '-q', 'api']).stdout.decode().strip()
                observed = json.loads(command(['docker', 'inspect', container]).stdout)[0]['Image']
                passed(f'{label}_api_image_preserves_restored_evidence', observed == image
                    and target_api(run_path + '/evidence')['body'] == pair)
            recovery['application_images'] = {'previous': rollback_image, 'current': current}
            recovery['rollback_scope'] = 'Two reviewed local API images on this compatible schema; no arbitrary migration rollback guarantee.'
    finally:
        cleanup = command(target + ['down', '--volumes', '--remove-orphans'], check=False)
        recovery['restored_project_cleanup'] = cleanup.returncode == 0
    passed('restored_test_stack_cleaned_up', recovery['restored_project_cleanup'])
