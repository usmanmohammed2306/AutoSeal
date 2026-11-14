"""Trusted offline training utilities. Generated candidates never enter here."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def identity(content):
    return 'sha256:' + hashlib.sha256(content).hexdigest()


def write_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(canonical(value))


def files_manifest(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('checkpoint contains a symbolic link')
        if path.is_file():
            digest = hashlib.sha256()
            with path.open('rb') as source:
                for block in iter(lambda: source.read(8 * 1024 * 1024), b''):
                    digest.update(block)
            result[path.relative_to(root).as_posix()] = {'sha256': digest.hexdigest(), 'bytes': path.stat().st_size}
    return result


def check_sources(root, expected):
    for name, digest in expected.items():
        if Path(name).name != name or identity((root / name).read_bytes()) != digest:
            raise ValueError('trusted training source differs from its frozen identity')


def loss_token_counts(rows, *, completion_only):
    """Check the trainer's actual preprocessed masks before optimization."""
    counts = []
    for row in rows:
        tokens = row['input_ids']
        if completion_only:
            mask = row.get('completion_mask')
            if (not mask or len(mask) != len(tokens) or set(mask) != {0, 1}
                    or mask != sorted(mask) or mask[0] != 0):
                raise ValueError('completion-only SFT requires a real prompt/completion loss mask')
            count = sum(mask)
        else:
            count = len(tokens)
        if count < 1:
            raise ValueError('training example has no supervised tokens')
        counts.append(count)
    if not counts:
        raise ValueError('SFT requires a nonempty supervised dataset')
    return counts


@contextmanager
def staged_model(source, expected, *, max_bytes=32 * 1024**3, progress=lambda *_: None):
    if not expected or not any(name.endswith('.safetensors') for name in expected):
        raise ValueError('frozen model weight identities are required')
    total = sum(item['bytes'] for item in expected.values())
    temporary = os.environ.get('SLURM_TMPDIR', '/tmp')
    if total > max_bytes or shutil.disk_usage(temporary).free < 2 * total + 1024**3:
        raise ValueError('insufficient bounded node-local model staging space')
    with tempfile.TemporaryDirectory(prefix='autoseal-training-model-', dir=temporary) as folder:
        root = Path(folder); root.chmod(0o700)
        progress('MODEL_STAGING', {'bytes': total})
        for name, item in sorted(expected.items()):
            if Path(name).name != name or item['bytes'] <= 0:
                raise ValueError('noncanonical model file inventory')
            path = source / name
            if path.stat().st_size != item['bytes']:
                raise ValueError('cached model file size changed')
            digest = hashlib.sha256()
            with path.open('rb') as original, (root / name).open('xb') as target:
                for block in iter(lambda: original.read(8 * 1024 * 1024), b''):
                    digest.update(block); target.write(block)
            if digest.hexdigest() != item['sha256']:
                raise ValueError('cached model bytes differ from the frozen checkpoint')
        progress('MODEL_VERIFIED', {'model_identity': identity(canonical(expected))})
        yield root


def verify_resume(checkpoint, *, configuration_id, dataset_id, base_identity):
    proof = json.loads((checkpoint / 'autoseal-resume.json').read_bytes())
    if (proof['configuration_id'] != configuration_id or proof['dataset_id'] != dataset_id
            or proof['base_identity'] != base_identity):
        raise ValueError('resume checkpoint belongs to another configuration, dataset or base model')
    expected = proof['checkpoint_files']
    observed = files_manifest(checkpoint)
    observed.pop('autoseal-resume.json', None)
    if expected != observed:
        raise ValueError('resume checkpoint bytes changed')
    state = json.loads((checkpoint / 'trainer_state.json').read_bytes())
    if state['global_step'] != proof['global_step']:
        raise ValueError('resume checkpoint step differs from trainer state')
    return proof
