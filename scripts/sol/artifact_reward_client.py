"""Multi-task GRPO reward transport. Never executes a generated file."""

import json
from pathlib import Path
import time

from reward_client import canonical, identity, validate_response, write_once


class ArtifactRewardClient:
    def __init__(self, exchange, manifest, manifest_id, tasks, *, arm, seed, receipts=(), timeout=300):
        if (identity(manifest) != manifest_id or arm not in {'vulnerable', 'sealed'}
                or seed not in manifest['seeds'] or not 0 < timeout <= 600):
            raise ValueError('unfrozen artifact reward condition')
        self.exchange, self.manifest, self.manifest_id = Path(exchange), manifest, manifest_id
        self.arm, self.seed, self.timeout = arm, seed, timeout
        self.tasks = {row['task_id']: row for row in tasks}
        if set(self.tasks) != set(manifest['tasks']):
            raise ValueError('trainer task membership differs from its reward manifest')
        self.receipts = list(receipts)
        if [row['batch'] for row in self.receipts] != list(range(len(self.receipts))):
            raise ValueError('resume reward history is not a contiguous prefix')

    def __call__(self, completions, *, task_id, prompts, **kwargs):
        batch = len(self.receipts)
        if batch >= self.manifest['max_batches_per_seed']:
            raise RuntimeError('frozen artifact rollout budget exhausted')
        count = self.manifest['batch_size']
        if (len(completions) != count or len(task_id) != count or len(set(task_id)) != 1
                or len(prompts) != count or task_id[0] not in self.tasks):
            raise ValueError('GRPO group must contain four generations of one frozen train prompt')
        task = self.tasks[task_id[0]]
        expected = [{'role': 'system', 'content': task['system']}, {'role': 'user', 'content': task['prompt']}]
        if any(prompt != expected for prompt in prompts):
            raise ValueError('reward callback prompt differs from the frozen train example')
        texts = [item if isinstance(item, str) else item[0]['content'] for item in completions]
        if any(not isinstance(text, str) or len(text.encode()) > self.manifest['max_completion_bytes'] for text in texts):
            raise ValueError('artifact completion exceeds the frozen byte bound')
        request = {'kind': 'artifact_study_reward_request', 'schema_version': 1,
            'bridge_manifest_id': self.manifest_id, 'arm': self.arm, 'seed': self.seed, 'batch': batch,
            'task_id': task['task_id'], 'prompt_id': task['prompt_id'], 'completions': texts}
        request_id = identity(request)
        path = request_id[7:] + '.json'
        write_once(self.exchange / 'requests' / path, canonical(request))
        response_file = self.exchange / 'responses' / path
        deadline = time.monotonic() + self.timeout
        while not response_file.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError('Mac artifact reward broker did not respond to ' + request_id)
            time.sleep(.25)
        if response_file.is_symlink() or response_file.stat().st_size > 150 * 1024:
            raise ValueError('invalid artifact reward response path or size')
        envelope = json.loads(response_file.read_bytes())
        rewards = validate_response(envelope, request_id, self.manifest_id, count)
        if any(value not in (0., 1.) for value in rewards):
            raise ValueError('artifact study uses binary task rewards only')
        self.receipts.append({'batch': batch, 'task_id': task['task_id'], 'prompt_id': task['prompt_id'],
            'request_id': request_id, 'response_id': envelope['response_id'],
            'rewards': rewards, 'outcomes': envelope['response']['outcomes'],
            'nonconstant': len(set(rewards)) > 1})
        print(json.dumps({'stage': 'MAC_REWARD', 'batch': batch, 'task_id': task['task_id'],
            'rewards': rewards, 'nonconstant': len(set(rewards)) > 1}), flush=True)
        return rewards
