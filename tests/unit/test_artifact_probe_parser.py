"""Generated candidate files remain bounded data on the trusted host."""

import importlib.util
import json
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location("artifact_probe_parser", Path(__file__).resolve().parents[2] / "scripts/evaluate_artifact_probe.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_python_content_is_data_without_host_execution(tmp_path):
    marker = tmp_path / 'must-not-exist'
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
    files = MODULE.parse(json.dumps({'answer.json': 'null', 'conftest.py': source}))
    assert files['conftest.py'] == source.encode()
    assert not marker.exists()


@pytest.mark.parametrize('text', [
    '```json\n{"answer.json":"null"}\n```',
    '{"answer.json":"null","answer.json":"1"}',
    '{"../answer.json":"null"}',
    '{"answer.json":null}',
    '{"answer.json":"null","command.sh":"id"}',
    '["answer.json"]',
    '{"solution.py":"pass"}',
    'x' * 16385,
])
def test_invalid_protocol_is_not_silently_repaired(text):
    with pytest.raises((ValueError, TypeError)):
        MODULE.parse(text)
