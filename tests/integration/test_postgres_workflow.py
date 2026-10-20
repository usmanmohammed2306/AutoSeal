"""Real API intent to worker to Docker to PostgreSQL/CAS integration."""

import os
from pathlib import Path
import uuid

from fastapi.testclient import TestClient
import pytest

from autoseal.api import create_app


pytestmark = pytest.mark.docker


def test_postgres_worker_docker_evidence_round_trip(tmp_path: Path) -> None:
    database_url = os.environ.get("AUTOSEAL_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("AUTOSEAL_TEST_DATABASE_URL is not configured")
    app = create_app(database_url, tmp_path / "evidence")
    with TestClient(app) as client:
        created = client.post(
            "/api/runs",
            json={"candidate": "exploit", "idempotency_key": str(uuid.uuid4())},
        )
        assert created.status_code == 202, created.text
        run_id = created.json()["id"]
        processed = app.state.run_service.process_one()
        assert processed is not None and processed.id == run_id
        assert processed.state == "COMPLETED"
        response = client.get(f"/api/runs/{run_id}/evidence")
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["classification"] == "FALSE_REWARD"
        assert report["proxy"]["image_identity"] == report["audit"]["image_identity"]
        assert report["proxy"]["candidate_identity"] == report["audit"]["candidate_identity"]
