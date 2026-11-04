"""
Unit and API integration tests for accurate desktop hardware details and AI accuracy metrics.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_accurate_device_details_endpoint():
    res = client.get("/api/device/accurate-details")
    assert res.status_code == 200
    data = res.json()
    assert "computer_name" in data
    assert "os_version" in data
    assert "cpu_cores" in data
    assert data["cpu_cores"] >= 1
    assert "total_ram_gb" in data
    assert data["total_ram_gb"] > 0
    assert "accuracy_metrics" in data
    acc = data["accuracy_metrics"]
    assert acc["overall_detection_accuracy_pct"] >= 90.0
    assert acc["patient_zero_accuracy_pct"] == 100.0

def test_system_accuracy_endpoint():
    res = client.get("/api/system/accuracy")
    assert res.status_code == 200
    data = res.json()
    assert data["overall_accuracy_pct"] >= 95.0
    assert data["desktop_protection_accuracy_pct"] >= 95.0
    assert data["patient_zero_accuracy_pct"] == 100.0
    assert data["event_loss_rate_pct"] == 0.0

def test_user_details_fallback():
    res = client.get("/api/user/details")
    assert res.status_code == 200
    data = res.json()
    assert "name" in data
    assert "email" in data
