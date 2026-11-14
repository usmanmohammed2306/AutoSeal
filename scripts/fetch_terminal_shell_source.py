"""Fetch one reviewed, pinned public case without executing downloaded code.

Preserves the released license and benchmark canaries. The resulting source
is evaluation material and must not enter a model-training corpus.
"""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


REVISION = 'd8a29613235a0ef56a8b70b3142626a533da28c2'
BASE = f'https://raw.githubusercontent.com/few-sh/terminal-wrench/{REVISION}'
TASK = 'tasks/125/claude-opus-4.6/original_task'
FILES = {
    'LICENSE': ('LICENSE', 'a6cba85bc92e0cff7a450b1d873c0eaa2e9fc96bf472df0247a26bec77bf3ff9'),
    'instruction.md': (TASK + '/instruction.md', '53c32b21df12b5fe956e64fac61ad6042d09d8a209c9f49ef6dda519871d7791'),
    'task.toml': (TASK + '/task.toml', 'fc071c76fcf1229a60a328502d244a7bf425fd6b30be6bf7e3812aa6f7ff5f84'),
    'original_task/environment/Dockerfile': (TASK + '/environment/Dockerfile', 'b61e49f75241828dda7c344f99a473c3ef4c8ee4dcac42a89d68e7f9acdce70a'),
    'original_task/environment/draft_spec.md': (TASK + '/environment/draft_spec.md', '12342a92306c7a876facfe887954cb113be0fb6ad7eb4109649658d0d140ef0c'),
    'original_task/environment/weights.json': (TASK + '/environment/weights.json', 'd0c044625e246c3ed94d0409cc574943a86ba852221dc809b24289caf559cee4'),
    'original_task/solution/solve.sh': (TASK + '/solution/solve.sh', 'ed4099d664657fa5ce06d979d758cce151d5ca31eecbe46537c771c55bf0de72'),
    'original_task/tests/test.sh': (TASK + '/tests/test.sh', 'fc9835e405cbbb0389d09b6482294a11e8f7ea4b856ec88162b8239c8b4b4d67'),
    'original_task/tests/test_outputs.py': (TASK + '/tests/test_outputs.py', '1a85448e1d9bb9c029f7822965709a017f82d2eb3adcc689f3e8f35e093eeb3b'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, (relative, expected) in FILES.items():
        url = BASE + '/' + relative
        request = urllib.request.Request(url, headers={'User-Agent': 'AutoSeal-pinned-case-reproduction'})
        with urllib.request.urlopen(request, timeout=20) as response:
            content = response.read(128 * 1024 + 1)
        if len(content) > 128 * 1024 or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError('upstream source differs from the reviewed pinned bytes: ' + name)
        path = args.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
        rows.append({'path': name, 'url': url, 'sha256': expected, 'bytes': len(content)})
    (args.root / 'source-manifest.json').write_text(json.dumps({'revision': REVISION, 'files': rows,
        'scope': 'Evaluation-only source; original reporters retain discovery credit. Downloaded code has not been executed.'}, indent=2) + '\n')
    print(json.dumps({'revision': REVISION, 'verified_files': len(rows), 'bytes': sum(row['bytes'] for row in rows)}))


if __name__ == '__main__':
    main()
