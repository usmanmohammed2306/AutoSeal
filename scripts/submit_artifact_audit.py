"""Explicit one-A100 submission for an already frozen post-checkpoint audit.

No training reward service is connected. Ambiguous submission intents must be
reconciled with Slurm instead of retried as another supposedly independent run.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

from autoseal.artifact_audit import verify_audit_configuration
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--export-root', type=Path, required=True)
    parser.add_argument('--remote-root', required=True)
    parser.add_argument('--remote-python', required=True)
    parser.add_argument('--model-path', required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--environment', default='qwen3b')
    args = parser.parse_args()
    for path in (args.remote_root, args.remote_python, args.model_path):
        if not PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or ',' in path:
            raise ValueError('audit submission paths must be absolute without traversal or commas')
    if (args.ssh_host.startswith('-') or not re.fullmatch(r'[a-zA-Z0-9_.@-]+', args.ssh_host)
            or any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', value) for value in (args.account, args.environment))):
        raise ValueError('invalid existing SSH account or environment')
    submission = args.export_root / 'submission.json'
    if submission.exists():
        raise ValueError('audit submission intent exists; reconcile its actual scheduler state')
    store = ContentAddressedStore(args.case_root / 'evidence')
    index = json.loads((args.export_root / 'index.json').read_bytes())
    config_id = index['configuration_id']
    config = verify_audit_configuration(store, config_id)
    raw = (args.export_root / 'configuration.json').read_bytes()
    if store.get_bytes(config_id) != raw or config['allocation_ceiling'] != {'a100_gpus': 1, 'host_memory_gib': 48, 'wall_minutes': 20}:
        raise ValueError('audit export changed after final checkpoint freeze')
    files = {'configuration.json': base64.b64encode(raw).decode()}
    for name, ref in config['sources'].items():
        if Path(name).name != name:
            raise ValueError('nonflat trusted inference source')
        content = (args.export_root / name).read_bytes()
        if store.get_bytes(ref) != content:
            raise ValueError('inference source changed after freeze')
        files[name] = base64.b64encode(content).decode()
    if len(canonical_json(files)) > 512 * 1024:
        raise ValueError('audit source upload exceeded its byte budget')
    ssh = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host]
    upload = '''import base64,hashlib,json,pathlib,py_compile,sys
assert sys.version_info>=(3,9)
r=pathlib.Path(sys.argv[1]);r.mkdir(parents=True,exist_ok=False);r.chmod(0o700)
for name,content in json.load(sys.stdin).items():
 assert pathlib.Path(name).name==name
 p=r/name;p.write_bytes(base64.b64decode(content))
 if name.endswith('.py'):py_compile.compile(str(p),doraise=True)
 print(name,hashlib.sha256(p.read_bytes()).hexdigest())
'''
    result = subprocess.run(ssh + [shlex.join([args.remote_python, '-c', upload, args.remote_root])],
        input=canonical_json(files), capture_output=True, timeout=90)
    (args.export_root / 'upload-receipt.json').write_bytes(canonical_json({'exit_code': result.returncode,
        'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()}))
    result.check_returncode()
    uploaded = dict(line.split() for line in result.stdout.decode().splitlines())
    if uploaded != {name: hashlib.sha256(base64.b64decode(value)).hexdigest() for name, value in files.items()}:
        raise ValueError('remote audit source inventory differs after upload')
    intent = {'configuration_id': config_id, 'remote_root': args.remote_root, 'status': 'SUBMISSION_PENDING',
        'job_name': 'autoseal_audit_' + config_id[7:19], 'limit': config['allocation_ceiling']}
    with submission.open('xb') as stream:
        stream.write(canonical_json(intent))
    parameters = ['ALL', 'AUTOSEAL_AUDIT_ROOT=' + args.remote_root, 'AUTOSEAL_MODEL_PATH=' + args.model_path,
        'AUTOSEAL_MAMBA_ENV=' + args.environment]
    command = ['sbatch', '--parsable', '--account=' + args.account, '--job-name=' + intent['job_name'],
        '--gpus=a100:1', '--cpus-per-task=4', '--mem=48G', '--time=00:20:00', '--export=' + ','.join(parameters),
        '--output=' + args.remote_root + '/audit-%j.out', '--error=' + args.remote_root + '/audit-%j.err',
        args.remote_root + '/artifact_audit.sbatch']
    result = subprocess.run(ssh + [shlex.join(command)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    intent.update(status='SUBMITTED' if result.returncode == 0 else 'SUBMISSION_FAILED', exit_code=result.returncode,
        stdout=result.stdout.decode(), stderr=result.stderr.decode())
    submission.write_bytes(canonical_json(intent)); print(json.dumps(intent)); result.check_returncode()


if __name__ == '__main__':
    main()
