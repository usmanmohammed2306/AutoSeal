"""Read actual retained calibration, with no GPU or candidate execution."""

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from autoseal.api import create_app
from autoseal.sft_archive import calibration_view
from autoseal.storage import ContentAddressedStore, IntegrityError


ROOT = Path(__file__).resolve().parents[2] / 'research/experiments/2026-11-13-artifact-admission/syntax-sft-archive-02'
EVALUATION_ID = 'sha256:02e0c5c93fc4def3636dd2124bd3d0444815a5854feea4a4158eb61c42edc6f5'


@pytest.mark.archive
def test_actual_sft_calibration_reader_view_and_pinned_identity(tmp_path):
    if not (ROOT / 'archive.json').exists():
        pytest.skip('separately retained SFT archive not available')
    app = create_app(f"sqlite:///{tmp_path / 'api.db'}", tmp_path / 'evidence',
        sft_archive_root=ROOT, sft_evaluation_identity=EVALUATION_ID,
        operator_token='a' * 32, reader_token='b' * 32)
    with TestClient(app) as client:
        assert client.get('/api/research/sft-calibration').status_code == 401
        response = client.get('/api/research/sft-calibration', headers={'Authorization': 'Bearer ' + 'b' * 32})
        assert response.status_code == 200
        body = response.json()
        assert body['evaluation_id'] == EVALUATION_ID and body['global_step'] == 16
        assert len(body['curve']) == 16 and body['phases']['post_sft']['attempted'] == 8
        assert body['phases']['post_sft']['syntax_valid'] == 4
        assert body['phases']['post_sft']['audit_pass'] == 2
        assert 'optimizer.pt' not in response.text
    app = create_app(f"sqlite:///{tmp_path / 'wrong.db'}", tmp_path / 'wrong',
        sft_archive_root=ROOT, sft_evaluation_identity='sha256:' + '0' * 64)
    with TestClient(app) as client:
        assert client.get('/api/research/sft-calibration').status_code == 503


def test_missing_archive_and_half_config_are_explicit(tmp_path):
    app = create_app(f"sqlite:///{tmp_path / 'api.db'}", tmp_path / 'evidence')
    with TestClient(app) as client:
        assert client.get('/api/research/sft-calibration').status_code == 503
    with pytest.raises(ValueError, match='configured together'):
        create_app('sqlite://', tmp_path / 'other', sft_archive_root=ROOT)


@pytest.mark.archive
def test_curve_is_checked_against_saved_checkpoint_logs():
    if not (ROOT / 'archive.json').exists():
        pytest.skip('separately retained SFT archive not available')
    store = ContentAddressedStore(ROOT / 'evidence')
    evaluation = store.get_json(EVALUATION_ID)
    archive = store.get_json(evaluation['training_archive_id'])
    report = store.get_json(archive['report_id'])
    report['log_history'][0]['loss'] = 0.01
    archive['report_id'] = store.put_json(report)
    evaluation['training_archive_id'] = store.put_json(archive)
    with pytest.raises(IntegrityError, match='curve differs'):
        calibration_view(store, store.put_json(evaluation))
