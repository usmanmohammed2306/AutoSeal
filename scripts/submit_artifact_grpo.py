"""Submit one reviewed frozen study to an existing authorized class account.

Explicit CLI action only. Never creates an account, upgrades a cloud plan,
retries an ambiguous submission, changes other jobs or exports audit inputs.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess

from autoseal.artifact_pipeline import _assert_runtime, _manager
from autoseal.artifact_study_archive import verify_study_archive, verify_study_context
from autoseal.storage import ContentAddressedStore, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--export-root', type=Path, required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--remote-python', required=True)
    parser.add_argument('--remote-root', required=True)
    parser.add_argument('--exchange-base', required=True)
    parser.add_argument('--exchange-name', required=True)
    parser.add_argument('--model-path', required=True)
    parser.add_argument('--warm-adapter', required=True)
    parser.add_argument('--account', required=True)
    parser.add_argument('--environment', default='qwen3b')
    args = parser.parse_args()
    for path in (args.remote_root, args.remote_python, args.exchange_base, args.model_path, args.warm_adapter):
        if not PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or ',' in path:
            raise ValueError('owned scheduler paths must be absolute without traversal or commas')
    if args.ssh_host.startswith('-') or not re.fullmatch(r'[a-zA-Z0-9_.@-]+', args.ssh_host):
        raise ValueError('invalid SSH host')
    if any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,80}', name) for name in (args.account, args.environment, args.exchange_name)):
        raise ValueError('invalid existing account, environment or exchange name')
    submission = args.export_root / 'submission.json'
    if submission.exists():
        raise ValueError('submission intent already exists; reconcile its scheduler state instead of submitting twice')
    store = ContentAddressedStore(args.case_root / 'evidence')
    raw = (args.export_root / 'configuration.json').read_bytes()
    envelope = json.loads(raw)
    manifest, config = verify_study_context(store, envelope['manifest_id'])
    if (envelope['training_configuration'] != config
            or envelope['manifest'] != manifest.model_dump(mode='json')
            or envelope['configuration_id'] != manifest.training_configuration_id):
        raise ValueError('export envelope differs from its checked local study')
    minutes = 15 if manifest.scope == 'REWARD_PREFLIGHT' else 45
    if config['allocation_ceiling'] != {'a100_gpus': 1, 'host_memory_gib': 48, 'wall_minutes': minutes}:
        raise ValueError('study allocation differs from its reviewed one-A100 ceiling')
    if manifest.scope == 'FROZEN_PAIRED_STUDY':
        readiness = verify_study_archive(store, config['preflight_archive_id'])
        preflight = store.get_json(config['preflight_archive_id'])
        prior = store.get_json(preflight['manifest_id'])
        responsive = any(any(row.get('grad_norm', 0.) > 0 for row in store.get_json(condition['report_id']).get('log_history', []))
            for condition in preflight['conditions'].values())
        if (readiness['scope'] != 'REWARD_PREFLIGHT' or not readiness['training_complete']
                or readiness['nonconstant_reward_groups'] == 0 or not responsive
                or prior['dataset_revision'] != manifest.dataset_revision
                or prior['starting_checkpoint'] != manifest.starting_checkpoint):
            raise ValueError('final allocation requires a responsive, matching model preflight')
    for binding in manifest.tasks.values():
        for revision in (binding.parent_revision, binding.child_revision):
            _assert_runtime(store, _manager(store).load(revision))
    hidden = store.get_json(manifest.hidden_commitment)
    hidden_ids = {row['task_id'] for row in hidden['records']}
    hidden_prompts = {store.get_bytes(row['prompt_id']).decode() for row in hidden['records']}
    if ({row['task_id'] for row in config['tasks']} & hidden_ids
            or {row['prompt'] for row in config['tasks']} & hidden_prompts):
        raise ValueError('hidden audit data was included in the training export')
    files = {'configuration.json': base64.b64encode(raw).decode()}
    for name, ref in config['sources'].items():
        if Path(name).name != name:
            raise ValueError('trusted exported source names must be flat')
        content = (args.export_root / name).read_bytes()
        if store.get_bytes(ref) != content:
            raise ValueError('trusted exported source changed after freeze')
        files[name] = base64.b64encode(content).decode()
    if len(canonical_json(files)) > 512 * 1024:
        raise ValueError('trusted upload exceeds the bounded configuration budget')
    ssh = ['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh_host]
    exchange = str(PurePosixPath(args.exchange_base) / args.exchange_name)
    upload = '''import base64,hashlib,json,pathlib,py_compile,sys
assert sys.version_info>=(3,9)
r=pathlib.Path(sys.argv[1]);r.mkdir(parents=True,exist_ok=False);r.chmod(0o700)
e=pathlib.Path(sys.argv[2]);e.parent.mkdir(parents=True,exist_ok=True);e.mkdir(exist_ok=False);e.chmod(0o700)
files=json.load(sys.stdin)
for name,content in files.items():
 assert pathlib.Path(name).name==name
 (r/name).write_bytes(base64.b64decode(content))
 if name.endswith('.py'):py_compile.compile(str(r/name),doraise=True)
print(json.dumps({name:hashlib.sha256((r/name).read_bytes()).hexdigest() for name in files}))
'''
    result = subprocess.run(ssh + [shlex.join([args.remote_python, '-c', upload, args.remote_root, exchange])],
        input=canonical_json(files), capture_output=True, timeout=90)
    (args.export_root / 'upload-receipt.json').write_bytes(canonical_json({'exit_code': result.returncode,
        'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()}))
    result.check_returncode()
    uploaded = json.loads(result.stdout)
    for name, content in files.items():
        if uploaded[name] != hashlib.sha256(base64.b64decode(content)).hexdigest():
            raise ValueError('remote trusted source differs after upload')
    parameters = ['ALL', 'AUTOSEAL_STUDY_ROOT=' + args.remote_root, 'AUTOSEAL_MODEL_PATH=' + args.model_path,
        'AUTOSEAL_WARM_ADAPTER=' + args.warm_adapter, 'AUTOSEAL_EXCHANGE_ROOT=' + exchange,
        'AUTOSEAL_MAMBA_ENV=' + args.environment]
    job_name = 'autoseal_' + envelope['configuration_id'][7:19]
    intent = {'status': 'SUBMISSION_PENDING', 'manifest_id': envelope['manifest_id'],
        'configuration_id': envelope['configuration_id'], 'scope': manifest.scope, 'remote_root': args.remote_root,
        'exchange_base': args.exchange_base, 'exchange_name': args.exchange_name, 'job_name': job_name,
        'audit_inputs_exported': 0, 'limit': config['allocation_ceiling']}
    with submission.open('xb') as output:
        output.write(canonical_json(intent))
    command = ['sbatch', '--parsable', '--account=' + args.account, '--job-name=' + job_name,
        '--gpus=a100:1', '--cpus-per-task=4', '--mem=48G', '--time=' + f'00:{minutes:02d}:00',
        '--export=' + ','.join(parameters), '--output=' + args.remote_root + '/campaign-%j.out',
        '--error=' + args.remote_root + '/campaign-%j.err', args.remote_root + '/artifact_grpo.sbatch']
    result = subprocess.run(ssh + [shlex.join(command)], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    intent.update(status='SUBMITTED' if result.returncode == 0 else 'SUBMISSION_FAILED', exit_code=result.returncode,
        stdout=result.stdout.decode(), stderr=result.stderr.decode())
    submission.write_bytes(canonical_json(intent))
    print(json.dumps(intent)); result.check_returncode()


if __name__ == '__main__':
    main()
