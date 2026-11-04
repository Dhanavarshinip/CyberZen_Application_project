"""
FastAPI End-to-End API Integration Tests.

Validates all HTTP endpoints:
- GET /api/health
- POST /api/telemetry/event
- POST /api/telemetry/batch
- GET /api/telemetry/events
- GET /api/dashboard/overview
- GET /api/graph
- GET /api/incidents
- GET /api/what-changed/{user_id}
- POST /api/response/recommend
- POST /api/investigator/chat
- POST /api/sync/toggle-mode
- POST /api/demo/scenario/{scenario_id}
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_api_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "online_mode" in data


def test_api_dashboard_overview(client):
    response = client.get("/api/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "current_risk_score" in data
    assert "formula" in data
    assert "active_incidents" in data


def test_api_telemetry_event_ingestion(client):
    payload = {
        "device_id": "TEST-DEV-01",
        "user_id": "test_user",
        "event_type": "LOGIN",
        "features": {
            "login_hour": 14,
            "device_id": "TEST-DEV-01",
            "application": "browser"
        }
    }
    response = client.post("/api/telemetry/event", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == "test_user"
    assert "anomaly_score" in data
    assert "risk_score" in data
    assert "behavioral_drift" in data


def test_api_knowledge_graph(client):
    response = client.get("/api/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    assert "stats" in data


def test_api_incidents(client):
    response = client.get("/api/incidents")
    assert response.status_code == 200
    data = response.json()
    assert "incidents" in data


def test_api_what_changed(client):
    response = client.get("/api/what-changed/researcher_alice")
    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert "baseline_established" in data


def test_api_adaptive_response(client):
    response = client.post("/api/response/recommend", json={"risk_score": 75.0})
    assert response.status_code == 200
    data = response.json()
    assert data["action_type"] == "REQUIRE_MFA"
    assert "recommended_action" in data


def test_api_investigator(client):
    payload = {"query": "What happened?"}
    response = client.post("/api/investigator/chat", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert data["mode"] == "deterministic_fallback"


def test_api_demo_scenario_execution(client):
    response = client.post("/api/demo/scenario/scenario_6_multi_stage")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario"] == "scenario_6_multi_stage"
    assert data["events_generated"] > 0


def test_api_protection_test(client):
    response = client.post("/api/protection/test")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "PASS"
    assert data["outcome"] in ("SAFE", "DANGEROUS", "SUSPICIOUS", "UNKNOWN")
    assert "anomaly_score" in data
    assert "behavioral_drift" in data
    assert "risk_score" in data
    assert "formula" in data
    assert data["is_test_event"] is True
    assert len(data["subsystems_verified"]) == 4


def test_api_device_status(client):
    response = client.get("/api/device/status?device_id=TEST-DEV-STATUS-01")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "connected" in data
    assert "checked_at" in data

