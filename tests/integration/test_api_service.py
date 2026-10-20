from pathlib import Path

from fastapi.testclient import TestClient

from autoseal.api import create_app
from autoseal.db import Base
from autoseal.evaluation import compare_fixture


def _test_app(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'test.db'}"
    app = create_app(
        database_url,
        tmp_path / "evidence",
        evaluator=lambda candidate: compare_fixture(candidate).model_dump(mode="json"),
    )
    Base.metadata.create_all(app.state.run_service.sessions.kw["bind"])
    return app


def test_api_records_intent_worker_produces_verifiable_evidence(tmp_path: Path) -> None:
    app = _test_app(tmp_path)
    with TestClient(app) as client:
        created = client.post(
            "/api/runs", json={"candidate": "exploit", "idempotency_key": "one"}
        )
        assert created.status_code == 202
        run_id = created.json()["id"]
        assert created.json()["state"] == "QUEUED"
        repeated = client.post(
            "/api/runs", json={"candidate": "exploit", "idempotency_key": "one"}
        )
        assert repeated.json()["id"] == run_id
        assert client.get(f"/api/runs/{run_id}/evidence").status_code == 404

        processed = app.state.run_service.process_one()
        assert processed is not None and processed.state == "COMPLETED"
        assert client.get(f"/api/runs/{run_id}").json()["classification"] == "FALSE_REWARD"
        evidence = client.get(f"/api/runs/{run_id}/evidence")
        assert evidence.status_code == 200
        assert evidence.json()["classification"] == "FALSE_REWARD"
        events = client.get(f"/api/runs/{run_id}/events").json()
        assert [item["kind"] for item in events] == ["QUEUED", "RUNNING", "COMPLETED"]
        streamed = client.get(f"/api/runs/{run_id}/stream")
        assert "event: completed" in streamed.text


def test_api_rejects_unknown_fixture_and_missing_run(tmp_path: Path) -> None:
    with TestClient(_test_app(tmp_path)) as client:
        assert client.post("/api/runs", json={"candidate": "../../etc"}).status_code == 400
        assert client.get("/api/runs/missing").status_code == 404


def test_research_endpoints_return_real_fixture_evidence(tmp_path: Path) -> None:
    with TestClient(_test_app(tmp_path)) as client:
        graph = client.get("/api/research/fixtures/exploit/influence")
        assert graph.status_code == 200
        assert graph.json()["graph"]["edges"][-1]["support"] == "INTERVENTION"
        assert graph.json()["witness"]["essential_files"] == ["conftest.py"]
        assert client.get("/api/research/fixtures/positive/influence").status_code == 400
        plans = client.get("/api/research/repair-preview")
        assert plans.status_code == 200
        assert len(plans.json()["plans"]) >= 2
        promotion = client.get("/api/research/promotion-review")
        assert promotion.status_code == 200
        assert promotion.json()["disposition"] == "REJECTED"
        assert promotion.json()["termination_stress"]["repaired_verdict"] == "INCONCLUSIVE"
        assert promotion.json()["seal_evidence"] is None
        composed = client.get("/api/research/repair-plan-preview")
        assert composed.status_code == 200
        assert composed.json()["policy_rollback_exact"] is True
        assert composed.json()["provider_capability_proven"] is False
        upstream = client.get("/api/research/upstream-swesmith")
        assert upstream.status_code == 200
        assert [case["classification"] for case in upstream.json()["cases"]] == [
            "HISTORICAL_MISSING_TEST_FALSE_REWARD", "AGREEMENT_PASS", "AGREEMENT_REJECT"
        ]
        current = client.get("/api/research/upstream-swebench")
        assert current.status_code == 200
        assert [case["classification"] for case in current.json()["cases"]] == [
            "FALSE_REWARD", "AGREEMENT_REJECT", "AGREEMENT_REJECT", "AGREEMENT_PASS"
        ]
        repair = client.get("/api/research/upstream-swebench/repair-preview")
        assert repair.status_code == 200
        assert repair.json()["disposition"] == "ELIGIBLE_LOCAL"
        assert len(repair.json()["controls"]) == 6


def test_native_archive_api_serves_verified_receipts_and_raw_output(tmp_path: Path):
    with TestClient(_test_app(tmp_path)) as client:
        response = client.get("/api/research/native-swebench")
        assert response.status_code == 200
        controls = response.json()["controls"]
        assert len(controls) == 7
        assert all(row["native_adapter_parity"] for row in controls)
        exploit = next(row for row in controls if row["case"] == "xfail")
        assert exploit["native_resolved"] and not exploit["f2p_explicit_pass"]
        assert exploit["audit_verdict"] == "REJECT"
        assert all(row["audit_verdict"] == "PASS" for row in controls if row["case"] in {"gold", "gold_alternative"})
        output = client.get("/api/research/native-swebench/objects/" + exploit["artifacts"]["test_output.txt"][7:])
        assert output.status_code == 200 and "XFAIL" in output.json()["content"]
        assert client.get("/api/research/native-swebench/objects/not-a-digest").status_code == 400


def test_training_pilot_api_keeps_zero_signal_visible(tmp_path: Path):
    with TestClient(_test_app(tmp_path)) as client:
        response = client.get("/api/research/training-pilots")
        assert response.status_code == 200
        pilot = next(item for item in response.json()["pilots"] if item["id"] == "grpo_bridge_d")
        assert pilot["summary"]["paired_conditions_complete"]
        assert not pilot["summary"]["nonzero_within_batch_reward_variance"]
        assert not pilot["summary"]["downstream_improvement_established"]
        diagnostic_pair = next(item for item in response.json()["pilots"] if item["id"] == "grpo_bridge_i_paired")
        assert diagnostic_pair["summary"]["nonzero_within_batch_reward_variance"]
        assert diagnostic_pair["summary"]["identical_paired_adapter_seeds"] == [11]
        assert not diagnostic_pair["summary"]["downstream_improvement_established"]
        preflights = {item["id"]: item for item in response.json()["preflights"]}
        assert preflights["grpo_bridge_g"]["report_status"] == "FAILED"
        assert preflights["grpo_bridge_g"]["evaluator_failures"] == 1
        assert preflights["grpo_bridge_h"]["report_status"] == "COMPLETE"
        assert preflights["grpo_bridge_h"]["outcomes"] == {"INVALID_OUTPUT": 3, "REJECT": 1}
        assert preflights["grpo_bridge_h"]["reward_sum"] == 0
        assert preflights["grpo_bridge_i"]["report_status"] == "COMPLETE"
        assert preflights["grpo_bridge_i"]["reward_sum"] == 1 / 7
        assert preflights["grpo_bridge_i"]["max_gradient_norm"] > 0
        config_id = pilot["configuration_id"]
        content = client.get("/api/research/training-pilots/grpo_bridge_d/objects/" + config_id[7:])
        assert content.status_code == 200 and "GRPO_BRIDGE_SMOKE_ONLY" in content.json()["content"]
        assert client.get("/api/research/training-pilots/grpo_bridge_h/objects/" + preflights["grpo_bridge_h"]["report_id"][7:]).status_code == 200
        assert client.get("/api/research/training-pilots/bad/objects/" + config_id[7:]).status_code == 400
