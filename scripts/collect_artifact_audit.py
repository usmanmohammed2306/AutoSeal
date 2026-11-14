"""Collect bounded inference evidence without loading a model or optimizer."""

import argparse
import base64
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

from autoseal.artifact_audit import verify_audit_configuration, verify_audit_generation
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--export-root', type=Path, required=True)
    parser.add_argument('--remote-root', required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    if (not PurePosixPath(args.remote_root).is_absolute() or '..' in PurePosixPath(args.remote_root).parts
            or not re.fullmatch(r'[a-zA-Z0-9_.@-]+', args.ssh_host) or args.ssh_host.startswith('-')):
        raise ValueError('invalid owned audit collection location')
    store = ContentAddressedStore(args.case_root / 'evidence')
    index = json.loads((args.export_root / 'index.json').read_bytes())
    config = verify_audit_configuration(store, index['configuration_id'])
    submission = json.loads((args.export_root / 'submission.json').read_bytes())
    job = submission['stdout'].strip().split(';')[0]
    if not job.isdecimal() or submission['configuration_id'] != index['configuration_id']:
        raise ValueError('audit submission differs from its frozen configuration')
    args.root.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host]
    code = '''import base64,json,pathlib,sys
r=pathlib.Path(sys.argv[1]);j=sys.argv[2];files={};total=0
def add(name,limit,optional=False):
 global total
 p=r/name
 if optional and not p.exists():return
 assert not p.is_symlink() and p.is_file() and p.stat().st_size<=limit
 raw=p.read_bytes();total+=len(raw);assert total<=24*1024**2
 files[name]=base64.b64encode(raw).decode()
add('audit-'+j+'.out',8*1024**2);add('audit-'+j+'.err',8*1024**2)
add('generation-01/configuration.json',2*1024**2,True);add('generation-01/report.json',2*1024**2,True)
for i in range(136):add('generation-01/sample-%03d.json'%i,32768,True)
print(json.dumps(files))
'''
    result = subprocess.run(ssh + [shlex.join(['python3', '-c', code, args.remote_root, job])],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    if result.returncode or len(result.stdout) > 33 * 1024**2:
        raise RuntimeError('bounded audit evidence transfer failed: ' + result.stderr.decode(errors='replace')[:500])
    files = {name: store.put_bytes(base64.b64decode(value, validate=True)) for name, value in json.loads(result.stdout).items()}
    scheduler = subprocess.run(ssh + [shlex.join(['sacct', '-j', job, '--format=JobID,State,Elapsed,ExitCode', '-n'])],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True).stdout
    attempt = {'configuration_id': index['configuration_id'], 'scheduler_id': store.put_bytes(scheduler),
        'raw_logs': {stream: files['audit-' + job + '.' + stream] for stream in ('out', 'err')}}
    (args.root / 'attempt.json').write_bytes(canonical_json(attempt))
    if 'generation-01/report.json' not in files:
        raise RuntimeError('scheduler and raw logs retained; no completed audit report exists')
    if store.get_json(files['generation-01/configuration.json']) != config:
        raise ValueError('remote audit configuration changed')
    report_id = files['generation-01/report.json']
    report = store.get_json(report_id)
    sample_ids = [files[f'generation-01/sample-{index:03d}.json'] for index in range(len(report['samples']))]
    archive = {'kind': 'artifact_study_audit_archive', 'schema_version': 1, **attempt,
        'report_id': report_id, 'sample_ids': sample_ids,
        'collection_source_id': store.put_bytes(Path(__file__).read_bytes())}
    identity = store.put_json(archive)
    (args.root / 'archive.json').write_bytes(canonical_json({'archive_id': identity}))
    _, checked = verify_audit_generation(store, identity)
    (args.root / 'verification.json').write_bytes(canonical_json({'archive_id': identity,
        'generation_status': checked['status'], 'samples': len(checked['samples']), 'audit_labels_computed': False}))
    print(json.dumps({'archive_id': identity, 'generation_status': checked['status'], 'samples': len(checked['samples'])}))


if __name__ == '__main__':
    main()
