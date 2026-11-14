"""Bounded SSH relay from owned Sol scratch to the Mac admission broker."""

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import time

from autoseal.artifact_study import StudyRewardWorker
from autoseal.storage import IntegrityError, canonical_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--manifest-id', required=True)
    parser.add_argument('--ssh-host', required=True)
    parser.add_argument('--ssh-socket', required=True)
    parser.add_argument('--remote-helper', required=True)
    parser.add_argument('--remote-python', default='python3', help='Existing Python 3.9+ interpreter on the login host.')
    parser.add_argument('--exchange-base', required=True)
    parser.add_argument('--exchange-name', required=True)
    parser.add_argument('--max-seconds', type=int, default=1200)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    if (not 1 <= args.max_seconds <= 3600 or args.ssh_host.startswith('-')
            or not re.fullmatch(r'[a-zA-Z0-9_.@-]+', args.ssh_host)
            or not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', args.exchange_name)
            or not all(PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                for path in (args.remote_helper, args.exchange_base))):
        raise ValueError('invalid owned transport paths or budget')
    worker = StudyRewardWorker(args.root, args.manifest_id)
    remote_root = str(PurePosixPath(args.exchange_base) / args.exchange_name)
    def exchange(action, payload=None):
        remote = shlex.join(['env', 'AUTOSEAL_EXCHANGE_BASE=' + args.exchange_base,
            args.remote_python, args.remote_helper, action, '--root', remote_root])
        process = subprocess.run(['ssh', '-S', args.ssh_socket, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            args.ssh_host, remote], input=None if payload is None else canonical_json(payload),
            capture_output=True, timeout=30)
        if process.returncode or len(process.stdout) > 150 * 1024:
            raise RuntimeError('owned reward transport failed: ' + process.stderr.decode(errors='replace')[:500])
        return json.loads(process.stdout)
    deadline = time.monotonic() + args.max_seconds
    while time.monotonic() < deadline:
        pending = exchange('pending')
        if pending is None:
            if args.once:
                return 0
            time.sleep(1)
            continue
        request_id = worker.store.put_json(pending['request'])
        if request_id != pending['request_id']:
            raise IntegrityError('remote artifact request identity changed')
        response_id = worker.evaluate(request_id)
        response = worker.store.get_json(response_id)
        acknowledgement = exchange('respond', {'response_id': response_id, 'response': response})
        if acknowledgement != {'response_id': response_id}:
            raise IntegrityError('artifact reward response acknowledgement changed')
        print(json.dumps({'request_id': request_id, 'response_id': response_id, 'status': response['status'],
            'outcomes': response['outcomes']}), flush=True)
        if response['status'] != 'COMPLETE':
            return 1
        if args.once:
            return 0
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
