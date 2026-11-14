"""Run a frozen condition matrix sequentially within one owned allocation."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from training_runtime import canonical, identity, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--warm-adapter', type=Path, required=True)
    parser.add_argument('--exchange', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_bytes())
    manifest = config['manifest']
    if identity(canonical(manifest)) != config['manifest_id']:
        raise ValueError('campaign manifest changed')
    args.output.mkdir(parents=True, exist_ok=False)
    planned = []
    for index, seed in enumerate(manifest['seeds']):
        arms = ('vulnerable', 'sealed') if index % 2 == 0 else ('sealed', 'vulnerable')
        planned += [{'arm': arm, 'seed': seed, 'status': 'NOT_RUN'} for arm in arms]
    report = {'kind': 'artifact_grpo_campaign', 'schema_version': 1, 'manifest_id': config['manifest_id'],
        'configuration_id': config['configuration_id'], 'scope': manifest['scope'], 'conditions': planned,
        'status': 'INCOMPLETE', 'error': None}
    write_new(args.output / 'plan.json', report)
    for condition in planned:
        directory = args.output / f"{condition['arm']}-{condition['seed']}"
        command = [sys.executable, str(Path(__file__).parent / 'artifact_grpo.py'), '--config', str(args.config),
            '--model', str(args.model), '--warm-adapter', str(args.warm_adapter), '--exchange', str(args.exchange),
            '--output', str(directory), '--arm', condition['arm'], '--seed', str(condition['seed'])]
        print(json.dumps({'stage': 'CONDITION_START', 'arm': condition['arm'], 'seed': condition['seed']}), flush=True)
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, check=False)
        condition['process_exit_code'] = completed.returncode
        path = directory / 'report.json'
        if path.exists():
            raw = path.read_bytes(); observed = json.loads(raw)
            condition.update(status=observed['status'], report_id=identity(raw),
                global_step=observed['global_step'], nonconstant_reward_groups=observed['nonconstant_reward_groups'])
        else:
            condition.update(status='FAILED_WITHOUT_REPORT')
        (args.output / 'progress.json').write_bytes(canonical(report))
        if completed.returncode != 0 or condition['status'] != 'COMPLETE':
            report['status'] = 'FAILED'; report['error'] = 'Condition failed; remaining conditions are explicitly NOT_RUN.'
            write_new(args.output / 'report.json', report)
            return 1
    report['status'] = 'COMPLETE'
    report['nonconstant_reward_groups'] = sum(row['nonconstant_reward_groups'] for row in planned)
    report['next_gate'] = ('Inspect reward contrast and model-output quality before freezing the final multi-seed study.'
        if manifest['scope'] == 'REWARD_PREFLIGHT' else 'Freeze all checkpoints before exporting hidden audit inputs.')
    write_new(args.output / 'report.json', report)
    print(json.dumps(report), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
