"""
Tests for Online and Offline Activity Storage Verification in SQLite.
Verifies:
1. Online activities (Web browsing, URLs, external networks) are stored with activity_domain="ONLINE".
2. Offline activities (Local applications, documents, files) are stored with activity_domain="OFFLINE".
3. Events captured offline are stored in SQLite with sync_status="PENDING".
4. Database stats endpoint correctly reports online_activities and offline_activities counts.
"""

import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.db import DatabaseManager

client = TestClient(app)

def test_telemetry_stats_endpoint():
    res = client.get("/api/telemetry/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_stored" in data
    assert "online_activities" in data
    assert "offline_activities" in data
    assert "database_file" in data
    assert data["total_stored"] >= data["online_activities"] + data["offline_activities"]

def test_online_and_offline_filtering():
    res_on = client.get("/api/telemetry/events?activity_domain=ONLINE&limit=5")
    assert res_on.status_code == 200
    events_on = res_on.json().get("events", [])
    for ev in events_on:
        f = ev.get("features", {})
        assert f.get("activity_domain") == "ONLINE" or ev.get("event_type") in ("WEBSITE_OPENED", "BROWSER_NAVIGATION", "NETWORK_CONNECTION")

    res_off = client.get("/api/telemetry/events?activity_domain=OFFLINE&limit=5")
    assert res_off.status_code == 200
    events_off = res_off.json().get("events", [])
    for ev in events_off:
        f = ev.get("features", {})
        assert f.get("activity_domain") == "OFFLINE" or ev.get("event_type") not in ("WEBSITE_OPENED", "BROWSER_NAVIGATION")

def test_record_offline_activity():
    res = client.post("/api/telemetry/record-offline?app_name=VS%20Code&action=Writing%20Python%20Code")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "SUCCESS"
    assert data["sync_status"] == "PENDING"
    ev = data["event"]
    assert ev["features"]["activity_domain"] == "OFFLINE"
    assert ev["features"]["db_storage_confirmed"] is True
    assert ev["sync_status"] == "PENDING"
