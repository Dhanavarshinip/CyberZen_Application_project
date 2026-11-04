import os
import json
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.monitoring.process_monitor import ProcessMonitor

client = TestClient(app)

def test_extension_pairing_and_heartbeat_lifecycle():
    """
    Validates:
    - User registration automatically pairs extension
    - POST /api/extension/pair creates/updates pairing credentials for authenticated user
    - GET /api/extension/active-pairing returns credentials for extension auto-discovery
    - POST /api/extension/heartbeat updates real-time heartbeat and connection status
    - GET /api/extension/status accurately reflects connected status
    """
    unique_suffix = uuid.uuid4().hex[:8]
    test_email = f"analyst_{unique_suffix}@cyberthreat.ai"
    test_device = f"DEV_TEST_{unique_suffix}"

    # 1. Register a real user
    signup_res = client.post("/api/auth/signup", json={
        "name": "Security Analyst",
        "email": test_email,
        "password": "Password123!",
        "device_id": test_device
    })
    assert signup_res.status_code == 200
    signup_data = signup_res.json()
    token = signup_data.get("token")
    user_id = signup_data["user"]["id"]

    # 2. Pair Extension with token
    pair_res = client.post(
        "/api/extension/pair",
        json={
            "email": test_email,
            "device_id": test_device,
            "user_id": user_id
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert pair_res.status_code == 200
    pair_data = pair_res.json()
    assert pair_data["status"] in ("SUCCESS", "paired")
    assert pair_data["user_email"] == test_email
    assert pair_data["device_id"] == test_device

    # 3. Verify active-pairing endpoint
    active_res = client.get("/api/extension/active-pairing")
    assert active_res.status_code == 200
    active_data = active_res.json()
    assert active_data["user_email"] == test_email
    assert active_data["device_id"] == test_device

    # 4. Extension Heartbeat
    hb_res = client.post("/api/extension/heartbeat", json={
        "user_email": test_email,
        "device_id": test_device,
        "version": "1.0.0"
    })
    assert hb_res.status_code == 200
    hb_data = hb_res.json()
    assert hb_data["status"] in ("connected", "HEALTHY")

    # 5. Status reflects connected
    status_res = client.get(f"/api/extension/status?device_id={test_device}")
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["connected"] is True
    assert status_data["user_email"] == test_email
    assert status_data["device_id"] == test_device


def test_process_monitor_preserves_actual_process_creation_time():
    """
    Validates that ProcessMonitor extracts actual process creation time
    from psutil instead of stamping all running processes with the current instant.
    """
    pm = ProcessMonitor()
    procs = pm.scan_running_processes()
    assert len(procs) > 0

    # Collect timestamps
    timestamps = [p.get("timestamp") for p in procs if p.get("timestamp")]
    assert len(timestamps) > 0

    # Ensure timestamps are not all identical (which was the bug causing 11:13 AM on all cards)
    unique_timestamps = set(timestamps)
    assert len(unique_timestamps) > 1, "Process monitor must yield varied, authentic creation times across active processes!"


def test_activity_view_has_no_user_facing_stored_in_sql():
    """
    Validates that user-facing 'Stored in SQL' or 'Stored in SQLite' text has been removed
    from ActivityView.jsx.
    """
    filepath = os.path.join(os.path.dirname(__file__), "..", "src", "components", "ActivityView.jsx")
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Ensure no visible strings of "Stored in SQLite" or "Stored in SQL"
    assert "Stored in SQLite" not in content, "ActivityView must not display 'Stored in SQLite' to user!"
    assert "Stored in SQL" not in content, "ActivityView must not display 'Stored in SQL' to user!"
    assert "Table 'events'" not in content, "ActivityView must not display database table internals!"
    assert "Queued in SQLite" not in content, "ActivityView must not display technical database queues!"


def test_browser_activity_recording_associates_correct_user_and_device():
    """
    Validates that telemetry recorded by the Chrome Extension via /api/browser/event
    is stored with the correct user and device isolation.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    test_device = f"DEV_BROWSER_{unique_suffix}"
    test_email = f"browser_user_{unique_suffix}@cyberthreat.ai"

    # Register user
    signup_res = client.post("/api/auth/signup", json={
        "name": "Browser Tester",
        "email": test_email,
        "password": "Password123!",
        "device_id": test_device
    })
    assert signup_res.status_code == 200
    user_id = signup_res.json()["user"]["id"]

    evt_payload = {
        "url": "https://cyberthreat.ai/safe-page",
        "title": "CyberThreat AI Official Documentation",
        "device_id": test_device,
        "user_id": user_id,
        "user_email": test_email,
        "activity_domain": "ONLINE",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    res = client.post("/api/browser/event", json=evt_payload)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] in ("SAFE", "SUCCESS")

    # Query events for this device and user
    events_res = client.get(f"/api/telemetry/events?device_id={test_device}")
    assert events_res.status_code == 200
    events = events_res.json().get("events", [])
    assert any(
        e.get("features", {}).get("url") == "https://cyberthreat.ai/safe-page" or
        e.get("features", {}).get("domain") == "cyberthreat.ai"
        for e in events
    )
