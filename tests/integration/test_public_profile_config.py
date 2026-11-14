"""Inspect the merged deployment config without starting services or ACME."""

import json
import os
from pathlib import Path
import subprocess

import pytest


pytestmark = pytest.mark.docker
ROOT = Path(__file__).resolve().parents[2]


def test_public_profile_exposes_only_proxy_and_keeps_execution_disabled():
    env = dict(os.environ, AUTOSEAL_DB_PASSWORD='synthetic-config-password', AUTOSEAL_OPERATOR_TOKEN='o' * 32,
        AUTOSEAL_READER_TOKEN='r' * 32, AUTOSEAL_STUDIO_USER='synthetic-reader',
        AUTOSEAL_STUDIO_PASSWORD='synthetic-config-password', AUTOSEAL_API_IMAGE='sha256:' + '1' * 64,
        AUTOSEAL_STUDIO_IMAGE='sha256:' + '2' * 64, AUTOSEAL_PROXY_IMAGE='sha256:' + '3' * 64,
        AUTOSEAL_HOST='198.51.100.23', AUTOSEAL_MODEL_EVIDENCE_DIR='/srv/autoseal/model-payload',
        AUTOSEAL_STUDY_ID='sha256:' + '4' * 64, AUTOSEAL_SFT_ID='sha256:' + '5' * 64)
    command = ['docker', 'compose', '-f', 'deploy/compose.archive.yaml', '-f', 'deploy/compose.public-review.yaml',
        '-f', 'deploy/compose.model-evidence.yaml', '--profile', 'public-review', 'config', '--format', 'json']
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    services = json.loads(result.stdout)['services']
    assert set(services) == {'db', 'migrate', 'api', 'studio', 'proxy'}
    assert not services['api'].get('ports') and not services['db'].get('ports')
    assert all(port['host_ip'] == '127.0.0.1' for port in services['studio']['ports'])
    assert {(port['host_ip'], str(port['published'])) for port in services['proxy']['ports']} == {
        ('0.0.0.0', '80'), ('0.0.0.0', '443')}
    for name in ('api', 'studio', 'proxy'):
        assert services[name]['cap_drop'] == ['ALL'] and services[name]['read_only'] is True
        assert not any('docker.sock' in item.get('target', '') for item in services[name].get('volumes', []))
        assert services[name]['image'].startswith('sha256:')
    assert services['studio']['environment']['AUTOSEAL_STUDIO_READ_ONLY'] == 'true'
    assert services['studio']['environment']['AUTOSEAL_API_TOKEN'] == 'r' * 32
    assert all(service['platform'] == 'linux/amd64' for service in services.values())
    assert services['api']['environment']['AUTOSEAL_STUDY_ID'] == 'sha256:' + '4' * 64
    mounted = [item for item in services['api']['volumes'] if item['target'] == '/srv/model-evidence']
    assert len(mounted) == 1 and mounted[0]['read_only'] is True
    assert mounted[0]['source'] == '/srv/autoseal/model-payload'
    assert all(service['logging']['options'] == {'max-file': '3', 'max-size': '10m'} for service in services.values())
    # Omitting a reviewed image must fail before Compose can start anything.
    del env['AUTOSEAL_API_IMAGE']
    refused = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
    assert refused.returncode != 0 and 'reviewed immutable API image' in refused.stderr
