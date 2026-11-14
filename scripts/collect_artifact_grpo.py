"""Retain a completed or failed GRPO campaign and its Mac reward ledger.

Copies checkpoints as bounded inert files, checks hashes, and recomputes
accepted rewards. No optimizer loading, model inference or job submission.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex
import sqlite3
import subprocess
import tempfile

from autoseal.artifact_study_archive import verify_study_archive
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--export-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--remote-root', required=True)
    args = parser.parse_args()
    if not PurePosixPath(args.remote_root).is_absolute() or '..' in PurePosixPath(args.remote_root).parts:
        raise ValueError('invalid owned remote root')
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.case_root / 'evidence')
    envelope = json.loads((args.export_root / 'configuration.json').read_bytes())
    manifest_id = envelope['manifest_id']
    ssh = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host]
    remaining = 1024**3
    def get(relative, *, expected=None, limit=4 * 1024**2):
        nonlocal remaining
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('noncanonical remote evidence path')
        code = ('import pathlib,sys; p=pathlib.Path(sys.argv[1]); '
            'assert not p.is_symlink() and p.is_file(); assert p.stat().st_size<=int(sys.argv[2]); '
            'sys.stdout.buffer.write(p.read_bytes())')
        command = ssh + [shlex.join(['python3', '-c', code,
            str(PurePosixPath(args.remote_root) / path), str(min(limit, remaining))])]
        with tempfile.TemporaryFile() as spool:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=spool, stderr=subprocess.PIPE,
                timeout=120)
            if result.returncode:
                raise RuntimeError(f'cannot retain {relative}: {result.stderr.decode(errors="replace")[:500]}')
            if spool.tell() > min(limit, remaining):
                raise ValueError('remote evidence exceeded its collection budget')
            spool.seek(0); raw = spool.read()
        if expected and (len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']):
            raise ValueError('collected training file differs from its frozen hash: ' + relative)
        remaining -= len(raw)
        return store.put_bytes(raw)
    submission = json.loads((args.export_root / 'submission.json').read_bytes())
    job = submission['stdout'].strip().split(';')[0]
    if not job.isdecimal():
        raise ValueError('invalid campaign scheduler ID')
    scheduler = subprocess.run(ssh + [shlex.join(['sacct', '-j', job, '--format=JobID,State,Elapsed,ExitCode', '-n'])],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True).stdout
    logs = {stream: get(f'campaign-{job}.{stream}', limit=8 * 1024**2) for stream in ('out', 'err')}
    attempt = {'kind': 'artifact_study_collection_attempt', 'manifest_id': manifest_id,
        'scheduler_id': store.put_bytes(scheduler), 'raw_logs': logs}
    (args.root / 'attempt.json').write_bytes(canonical_json({'attempt_id': store.put_json(attempt)}))
    try:
        campaign_id = get('campaign-01/report.json')
    except RuntimeError as exc:
        (args.root / 'unavailable-campaign.json').write_bytes(canonical_json({'error': str(exc),
            'scope': 'Scheduler and logs retained. No campaign completion or optimizer success inferred.'}))
        raise
    campaign = store.get_json(campaign_id)
    # Persist the result immediately, including failures before the first
    # optimizer update. Subsequent collection failures cannot erase it.
    (args.root / 'campaign.json').write_bytes(canonical_json(campaign))
    conditions = {}
    for row in campaign['conditions']:
        if row['status'] == 'NOT_RUN':
            continue
        name = f"{row['arm']}-{row['seed']}"
        if row['arm'] not in ('vulnerable', 'sealed') or type(row['seed']) is not int:
            raise ValueError('invalid condition directory')
        if row['status'] == 'FAILED_WITHOUT_REPORT':
            conditions[name] = {'missing_report': True}; continue
        prefix = 'campaign-01/' + name
        report_id = get(prefix + '/report.json')
        report = store.get_json(report_id)
        condition = {'report_id': report_id}
        if report['status'] == 'COMPLETE':
            step = report['global_step']
            if type(step) is not int or not 1 <= step <= 32 or report['checkpoint_relative_path'] != f'trainer/checkpoint-{step}':
                raise ValueError('invalid condition checkpoint directory')
            checkpoint = prefix + '/' + report['checkpoint_relative_path']
            proof_id = get(checkpoint + '/autoseal-resume.json')
            if store.get_json(proof_id) != report['checkpoint_manifest']:
                raise ValueError('remote checkpoint sidecar differs from its report')
            condition['checkpoint_files'] = {name: get(checkpoint + '/' + name, expected=item, limit=128 * 1024**2)
                for name, item in report['checkpoint_manifest']['checkpoint_files'].items()}
            condition['adapter_files'] = {name: get(prefix + '/adapter/' + name, expected=item, limit=128 * 1024**2)
                for name, item in report['adapter_files'].items()}
            condition['resume_proof_id'] = proof_id
        conditions[name] = condition
        (args.root / 'collection-progress.json').write_bytes(canonical_json({'conditions': conditions}))
    with sqlite3.connect(args.case_root / 'study-rewards.sqlite3') as connection:
        rows = connection.execute('SELECT arm,seed,batch,request,response FROM rewards WHERE manifest=? ORDER BY arm,seed,batch',
            (manifest_id,)).fetchall()
    ledger = [dict(zip(('arm', 'seed', 'batch', 'request_id', 'response_id'), row)) for row in rows]
    archive = {'kind': 'artifact_study_training_archive', 'schema_version': 1, 'manifest_id': manifest_id,
        'campaign_id': campaign_id, 'conditions': conditions, 'broker_batches': ledger,
        'scheduler_id': store.put_bytes(scheduler), 'raw_logs': logs,
        'collection_scope': 'Owned trusted Sol files and Mac scalar-reward ledger; optimizers are inert data.'}
    archive['collection_sources'] = {str(path): store.put_bytes(path.read_bytes()) for path in
        [Path(__file__), Path('src/autoseal/artifact_study_archive.py'), Path('scripts/relay_artifact_study.py')]}
    identity = store.put_json(archive)
    (args.root / 'archive.json').write_bytes(canonical_json({'archive_id': identity,
        'evidence_root': str(store.root.resolve())}))
    checked = verify_study_archive(store, identity)
    (args.root / 'verified.json').write_bytes(canonical_json(checked))
    print(json.dumps(checked))


if __name__ == '__main__':
    main()
