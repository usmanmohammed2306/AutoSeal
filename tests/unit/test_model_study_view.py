"""Missing or changed study evidence cannot become a product result."""

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from autoseal.api import create_app
from autoseal.cli import main
from autoseal.artifact_study_review import require_analysis_source
from autoseal.storage import ContentAddressedStore, IntegrityError


def test_reader_gets_explicit_unavailable_evidence_and_unknown_user_is_denied(tmp_path):
    app = create_app('sqlite://', tmp_path / 'evidence', operator_token='o' * 32, reader_token='r' * 32)
    with TestClient(app) as client:
        assert client.get('/api/research/model-study').status_code == 401
        assert client.get('/api/research/model-study', headers={'Authorization': 'Bearer ' + 'r' * 32}).status_code == 503
    with pytest.raises(ValueError, match='configured together'):
        create_app('sqlite://', tmp_path / 'other', study_archive_root=tmp_path)


def test_configured_missing_study_never_falls_back_to_a_zero_or_demo(tmp_path):
    app = create_app('sqlite://', tmp_path / 'evidence', study_archive_root=tmp_path,
        study_evaluation_identity='sha256:' + '0' * 64)
    with TestClient(app) as client:
        response = client.get('/api/research/model-study')
        assert response.status_code == 503 and 'summary' not in response.json()


def test_analysis_must_use_the_implementation_committed_before_training(tmp_path):
    store = ContentAddressedStore(tmp_path)
    source = Path(__file__).resolve().parents[2] / 'src/autoseal/artifact_audit.py'
    identity = store.put_bytes(source.read_bytes())
    protocol = {'implementation_id': identity}
    require_analysis_source(store, protocol, {'analysis_implementation_id': identity})
    changed = store.put_bytes(source.read_bytes() + b'\n# post-outcome method change\n')
    with pytest.raises(IntegrityError, match='frozen before training'):
        require_analysis_source(store, {'implementation_id': changed}, {'analysis_implementation_id': changed})
    with pytest.raises(IntegrityError, match='frozen before training'):
        require_analysis_source(store, protocol, {'analysis_implementation_id': changed})


def test_cli_refuses_missing_model_evidence_without_a_demo_result(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(['model-study', '--root', str(tmp_path), '--evaluation-id', 'sha256:' + '0' * 64])
    assert error.value.code == 2
    assert 'model study evidence invalid' in capsys.readouterr().err
