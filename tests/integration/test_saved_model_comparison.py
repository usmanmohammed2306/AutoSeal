"""Check the real retained study without launching Docker or a model.

Machine archives are optional and excluded from the public source package.
Counterfeit records go to a temporary overlay, never the original archive.
"""

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from autoseal.api import create_app
import autoseal.artifact_study_review as review
from autoseal.storage import ContentAddressedStore, IntegrityError


EXPERIMENT = Path(__file__).resolve().parents[2] / 'research/experiments/2026-11-13-artifact-admission'
ROOT = EXPERIMENT / 'study-cases-04'
pytestmark = pytest.mark.archive


@pytest.fixture
def retained(tmp_path, monkeypatch):
    path = EXPERIMENT / 'hidden-audit-evaluation-01/evaluation.json'
    if not path.exists():
        pytest.skip('separately retained model comparison not available')
    identity = json.loads(path.read_bytes())['evaluation_id']
    original = ContentAddressedStore(ROOT / 'evidence')

    class Overlay(ContentAddressedStore):
        def get_bytes(self, reference):
            if self._path(reference).exists():
                return super().get_bytes(reference)
            return original.get_bytes(reference)

    store = Overlay(tmp_path / 'overlay')
    monkeypatch.setattr(review, 'ContentAddressedStore', lambda _path: store)
    return store, identity


def test_actual_reader_api_recounts_all_seven_models_and_retains_null_effect(retained, tmp_path):
    _store, identity = retained
    app = create_app('sqlite://', tmp_path / 'api-evidence', operator_token='o' * 32,
        reader_token='r' * 32, study_archive_root=ROOT, study_evaluation_identity=identity)
    with TestClient(app) as client:
        response = client.get('/api/research/model-study', headers={'Authorization': 'Bearer ' + 'r' * 32})
    assert response.status_code == 200
    result = response.json()
    assert result['seeds'] == [11, 22, 33] and result['steps_per_condition'] == 8
    assert result['summary']['audit_complete'] is True
    assert len(result['summary']['models']) == 7
    assert all((row['attempts'], row['audit_passes'], row['false_rewards'], row['invalid_outputs'], row['inconclusive'])
        == (8, 1, 0, 0, 0) for row in result['summary']['models'])
    assert all(row['seed_differences'] == [0., 0., 0.] for row in result['summary']['paired_seed_contrasts'])
    assert sum(row['attempted_outputs'] for row in result['training_conditions']) == 192
    assert result['input_overlap_check']['exact_operation_input_overlaps'] == 0


@pytest.mark.parametrize('change', ['summary', 'duplicate_attempt', 'analysis_source'])
def test_content_addressed_counterfeit_study_is_still_refused(retained, change):
    store, identity = retained
    record = store.get_json(identity)
    if change == 'summary':
        record['summary']['models'][0]['audit_passes'] = 8
    elif change == 'duplicate_attempt':
        record['outcome_ids'][0] = record['outcome_ids'][1]
    else:
        record['analysis_implementation_id'] = store.put_bytes(b'post-outcome replacement analysis')
    forged = store.put_json(record)
    with pytest.raises(IntegrityError):
        review.study_review(ROOT, forged)
