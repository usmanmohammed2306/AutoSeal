"""Build the reviewed shell-task reproduction image; never a leaderboard score.

Only the reviewed original recipe and fixed dependency additions are used.
Building runs package setup; candidate execution belongs to the separate
networkless reproduction command. Keep original license and canaries intact.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

from fetch_terminal_shell_source import FILES, REVISION
from autoseal.execution import run_command
from autoseal.storage import ContentAddressedStore


BASE = 'ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--image', default='autoseal/terminal-shell-125:reproduced')
    parser.add_argument('--platform', choices=['linux/arm64', 'linux/amd64'], default='linux/arm64')
    args = parser.parse_args()
    if not re.fullmatch(r'autoseal/terminal-shell-125:[a-zA-Z0-9_.-]+', args.image):
        raise ValueError('use an AutoSeal-owned local image tag')
    for name, (_, expected) in FILES.items():
        path = args.source / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('reviewed source changed: ' + name)
    args.root.mkdir(parents=True, exist_ok=False)
    context = args.root / 'context'; context.mkdir()
    original = (args.source / 'original_task/environment/Dockerfile').read_text()
    recipe = original.replace('FROM ubuntu:24.04', 'FROM ' + BASE, 1)
    recipe += '''
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/autoseal-verifier && /opt/autoseal-verifier/bin/pip install --no-cache-dir pytest==8.4.1 iniconfig==2.3.1 packaging==26.3 pluggy==1.7.0 pygments==2.21.0
COPY tests /tests
COPY solve.sh /reference/solve.sh
COPY LICENSE /licenses/terminal-wrench/LICENSE
RUN cp -a /app /pristine-app
'''
    (context / 'Dockerfile').write_text(recipe)
    (context / 'tests').mkdir()
    for name in ['test.sh', 'test_outputs.py']:
        shutil.copyfile(args.source / 'original_task/tests' / name, context / 'tests' / name)
    shutil.copyfile(args.source / 'original_task/solution/solve.sh', context / 'solve.sh')
    shutil.copyfile(args.source / 'LICENSE', context / 'LICENSE')
    store = ContentAddressedStore(args.root / 'evidence')
    built = run_command(['docker', 'build', '--platform', args.platform, '--progress', 'plain', '-t', args.image, str(context)],
        timeout_seconds=600, max_output_bytes=128 * 1024)
    process_id = store.put_json(built.to_dict())
    image = None
    if built.exit_code == 0:
        inspected = run_command(['docker', 'image', 'inspect', args.image], timeout_seconds=10)
        inspect_id = store.put_json(inspected.to_dict())
        if inspected.exit_code != 0 or inspected.stdout_truncated:
            raise ValueError('cannot retain built image identity')
        image = json.loads(inspected.stdout)[0]['Id']
    else:
        inspect_id = None
    report = {'kind': 'reviewed_shell_recipe_build', 'source_revision': REVISION, 'base': BASE,
        'platform': args.platform, 'image': image, 'recipe_id': store.put_bytes(recipe.encode()),
        'build_process_id': process_id, 'image_inspection_id': inspect_id,
        'sources': {name: store.put_bytes((args.source / name).read_bytes()) for name in FILES},
        'limitations': ['Original task recipe plus pinned verifier dependencies; test bootstrap/harness not executed.',
            'Resolved image pins installed packages; future rebuilds must be revalidated, not assumed identical.']}
    identity = store.put_json(report)
    (args.root / 'report.json').write_text(json.dumps({'report_id': identity}, indent=2) + '\n')
    print(json.dumps({'report_id': identity, 'image': image, 'build_exit_code': built.exit_code}))
    return 0 if image else 1


if __name__ == '__main__':
    raise SystemExit(main())
