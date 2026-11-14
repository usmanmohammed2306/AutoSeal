"""Collect this project's completed SFT pilot through an existing SSH socket.

Copies declared files as inert bytes and checks each digest. Never loads a
pickle or submits a GPU job. A failed run report is retained before rejection.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shlex
import subprocess
import tempfile

from autoseal.sft_archive import verify_sft_archive
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen-root', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--remote-python', default='python3')
    parser.add_argument('--remote-root', required=True)
    args = parser.parse_args()
    if not PurePosixPath(args.remote_root).is_absolute() or '..' in PurePosixPath(args.remote_root).parts:
        raise ValueError('remote run root must be an absolute trusted path')
    args.root.mkdir(parents=True, exist_ok=False)
    store = ContentAddressedStore(args.root / 'evidence')
    original = ContentAddressedStore(args.frozen_root / 'evidence')
    budget = 320 * 1024**2
    def get(relative, *, expected=None, limit=4 * 1024**2):
        nonlocal budget
        path = PurePosixPath(relative)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('noncanonical remote output path')
        remote = str(PurePosixPath(args.remote_root) / path)
        code = ('from pathlib import Path; import sys; p=Path(sys.argv[1]); '
            'assert not p.is_symlink() and p.is_file(); '
            'assert p.stat().st_size <= int(sys.argv[2]); '
            'sys.stdout.buffer.write(p.read_bytes())')
        command = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host,
            shlex.join([args.remote_python, '-c', code, remote, str(min(limit, budget))])]
        with tempfile.TemporaryFile() as spool:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=spool, stderr=subprocess.PIPE,
                timeout=120, check=False)
            if result.returncode:
                raise RuntimeError(f'could not collect {relative}: {result.stderr.decode(errors="replace")}')
            size = spool.tell()
            if size > min(limit, budget):
                raise ValueError('remote output exceeded the collection budget')
            spool.seek(0); content = spool.read()
        if expected and (len(content) != expected['bytes'] or hashlib.sha256(content).hexdigest() != expected['sha256']):
            raise ValueError(f'remote file changed: {relative}')
        budget -= len(content)
        return store.put_bytes(content)
    # Preserve source, data reviews and the verified parent receipt. Files are
    # read through the original CAS verifier, never copied by trusting a name.
    for index, path in enumerate(sorted((args.frozen_root / 'evidence/objects').glob('*/*'))):
        if index >= 1024 or path.is_symlink() or path.stat().st_size > 8 * 1024**2:
            raise ValueError('unexpected frozen-input archive size or path')
        content = original.get_bytes('sha256:' + path.name)
        budget -= len(content)
        if budget < 0:
            raise ValueError('frozen archive exceeded the collection budget')
        store.put_bytes(content)
    config_id = store.put_bytes((args.frozen_root / 'configuration.json').read_bytes())
    parent_id = json.loads((args.frozen_root / 'pause-evidence.json').read_bytes())['evidence_id']
    parent = store.get_json(parent_id)
    report_id = get('resume-01/report.json')
    report = store.get_json(report_id)
    (args.root / 'collected-report.json').write_bytes(canonical_json(report))
    if report['status'] != 'COMPLETE':
        raise ValueError('SFT run is not complete; its report has been retained')
    baseline_id, validation_id = get('resume-01/baseline.json'), get('resume-01/validation.json')
    checkpoints = {}
    for phase, prefix, observed in (('pause', 'pause-01', parent['report']), ('resume', 'resume-01', report)):
        directory = f"{prefix}/{observed['checkpoint_relative_path']}"
        expected_directory = f"{prefix}/trainer/checkpoint-{observed['global_step']}"
        if directory != expected_directory:
            raise ValueError('unexpected checkpoint directory')
        checkpoints[phase] = {name: get(f'{directory}/{name}', expected=item, limit=128 * 1024**2)
            for name, item in observed['checkpoint_manifest']['checkpoint_files'].items()}
    adapter = {name: get(f'resume-01/adapter/{name}', expected=item, limit=128 * 1024**2)
        for name, item in report['adapter_files'].items()}
    jobs = [str(parent['report']['slurm_job_id']), str(report['slurm_job_id'])]
    if any(not job.isdecimal() for job in jobs):
        raise ValueError('unexpected Slurm job ID')
    command = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', args.ssh_host,
        shlex.join(['sacct', '-j', ','.join(jobs), '--format=JobID,State,Elapsed,ExitCode', '-n'])]
    scheduler = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True).stdout
    archive = {'kind': 'sft_pause_resume_archive', 'schema_version': 1, 'configuration_id': config_id,
        'pause_evidence_id': parent_id, 'report_id': report_id, 'baseline_id': baseline_id,
        'validation_id': validation_id, 'checkpoint_files': checkpoints, 'adapter_files': adapter,
        'scheduler_id': store.put_bytes(scheduler),
        'collection_scope': 'Owned SSH output; weights and optimizer are inert content-addressed bytes, never loaded on Mac.'}
    identity = store.put_json(archive)
    checked = verify_sft_archive(store, identity)
    (args.root / 'archive.json').write_bytes(canonical_json({'archive_id': identity}))
    print(json.dumps(checked))


if __name__ == '__main__':
    main()
