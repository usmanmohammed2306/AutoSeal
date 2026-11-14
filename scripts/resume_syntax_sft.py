"""Verify a planned pause through owned SSH, then resume the frozen budget.

Uses only a pre-existing scheduler account and cached model. It refuses to
submit if configuration, source, optimizer or scheduler evidence differs.
"""

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

from autoseal.storage import ContentAddressedStore, canonical_json


VERIFY = '''import hashlib,json,pathlib,sys
r=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(r))
from training_runtime import canonical,check_sources,identity,verify_resume
c=json.loads((r/'configuration.json').read_bytes())
assert identity((r/'configuration.json').read_bytes())==sys.argv[2]
check_sources(r,c['sources'])
report=json.loads((r/'pause-01/report.json').read_bytes())
assert report['status']=='PAUSED_AT_CHECKPOINT' and report['error'] is None
step=c['pause_test']['pause_at_step'];assert report['global_step']==step<c['max_steps']
checkpoint=r/'pause-01/trainer'/('checkpoint-'+str(step))
assert sum(p.stat().st_size for p in checkpoint.rglob('*') if p.is_file())<256*1024**2
proof=verify_resume(checkpoint,configuration_id=sys.argv[2],dataset_id=c['dataset_revision'],base_identity=identity(canonical(c['model_files'])))
assert proof==report['checkpoint_manifest']
if c.get('completion_only_loss'):
 assert report['completion_only_loss'] is True
 assert len(report['supervised_tokens_per_example'])==len(c['training_examples'])
 assert all(0<a<b for a,b in zip(report['supervised_tokens_per_example'],report['tokenized_example_lengths']))
baseline=json.loads((r/'pause-01/baseline.json').read_bytes())
assert baseline==json.loads((checkpoint/'autoseal-baseline.json').read_bytes())
print(json.dumps({'report':report,'proof':proof,'baseline':baseline}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--frozen-root', type=Path, required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--remote-root', required=True)
    parser.add_argument('--model-path', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--environment', default='qwen3b')
    args = parser.parse_args()
    for path in (args.remote_root, args.model_path):
        if not PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or ',' in path:
            raise ValueError('scheduler paths must be absolute trusted paths without commas')
    if any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', value) for value in (args.account, args.environment)):
        raise ValueError('invalid existing scheduler account or environment')
    if args.ssh_host.startswith('-') or not re.fullmatch(r'[a-zA-Z0-9_.@-]+', args.ssh_host):
        raise ValueError('invalid SSH host')
    local = args.frozen_root
    submission = local / 'submission-resume-01.json'
    if submission.exists():
        raise ValueError('a resume submission already exists; inspect it rather than submit twice')
    store = ContentAddressedStore(local / 'evidence')
    raw = (local / 'configuration.json').read_bytes()
    config = json.loads(raw); config_id = store.put_bytes(raw)
    ssh = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host]
    verified = subprocess.run(ssh + [shlex.join(['python3', '-c', VERIFY, args.remote_root, config_id])],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
    receipt = {'exit_code': verified.returncode, 'stdout': verified.stdout.decode(), 'stderr': verified.stderr.decode()}
    (local / 'pause-verification-command.json').write_bytes(canonical_json(receipt))
    verified.check_returncode()
    if len(verified.stdout) > 1024**2:
        raise ValueError('pause evidence exceeds its bound')
    body = json.loads(verified.stdout)
    job = str(body['report']['slurm_job_id'])
    if not job.isdecimal():
        raise ValueError('invalid parent Slurm job ID')
    scheduler = subprocess.run(ssh + [shlex.join(['sacct', '-j', job, '--format=JobID,State,Elapsed,ExitCode', '-n'])],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True).stdout
    lines = [line.split() for line in scheduler.decode().splitlines() if line.split() and line.split()[0] == job]
    if len(lines) != 1 or lines[0][1] != 'COMPLETED' or lines[0][-1] != '0:0':
        raise ValueError('parent job has not completed successfully; do not resume yet')
    proof_id = store.put_json(body)
    for name in ('report', 'proof', 'baseline'):
        (local / f'pause-{name}.json').write_bytes(canonical_json(body[name]))
    # Keep the established basename for collector compatibility.
    (local / 'baseline.json').write_bytes(canonical_json(body['baseline']))
    (local / 'pause-evidence.json').write_bytes(canonical_json({'evidence_id': proof_id}))
    (local / 'pause-scheduler.txt').write_bytes(scheduler)
    remote = args.remote_root
    step = config['pause_test']['pause_at_step']
    environment = ','.join(['ALL', 'AUTOSEAL_SFT_ROOT=' + remote, 'AUTOSEAL_MODEL_PATH=' + args.model_path,
        'AUTOSEAL_MAMBA_ENV=' + args.environment, 'AUTOSEAL_SFT_OUTPUT=' + remote + '/resume-01',
        'AUTOSEAL_RESUME_FROM=' + remote + f'/pause-01/trainer/checkpoint-{step}'])
    command = ['env', '-u', 'AUTOSEAL_PAUSE_STEP', 'sbatch', '--parsable', '--account=' + args.account,
        '--export=' + environment, '--output=' + remote + '/resume-%j.out', '--error=' + remote + '/resume-%j.err',
        remote + '/artifact_sft.sbatch']
    # Persist the submission intent first. An SSH timeout must not cause an
    # automatic duplicate job whose scheduler state is unknown.
    intent = {'phase': f'verified step-{step} resume to frozen step {config["max_steps"]}',
        'parent_pause_evidence': proof_id, 'configuration_id': config_id, 'remote_root': remote,
        'limit': config['allocation_limit_per_attempt'], 'status': 'SUBMISSION_PENDING'}
    with submission.open('xb') as output:
        output.write(canonical_json(intent))
    result = subprocess.run(ssh + [shlex.join(command)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    intent.update(status='SUBMITTED' if result.returncode == 0 else 'SUBMISSION_FAILED', exit_code=result.returncode,
        stdout=result.stdout.decode(), stderr=result.stderr.decode())
    submission.write_bytes(canonical_json(intent))
    print(json.dumps(intent)); result.check_returncode()


if __name__ == '__main__':
    main()
