"""
Tests for Date Filters, Timezone Boundaries, Device Isolation,
and Home Protection Status Evaluation.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from backend.main import app, db, real_monitor, sync_engine


@pytest.fixture
def client():
    return TestClient(app)


def test_date_query_exact_yesterday_and_today(client):
    """Verify that querying yesterday, today, and custom dates returns only records for that date."""
    dev_id = f"DEV-DATE-TEST-{uuid.uuid4().hex[:6]}"
    # Seed events for 2026-10-11 and 2026-10-12 in local IST (+330 min)
    ev_y = {
        "event_id": f"ev_date_y_{uuid.uuid4().hex[:6]}",
        "device_id": dev_id,
        "user_id": "date_test_user",
        "timestamp": "2026-10-11T10:00:00.000000+00:00",
        "event_type": "APPLICATION_START",
        "features": {"process_name": "notepad.exe", "is_test_event": False},
        "risk_score": 5.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": "2026-10-11T10:00:00.000000+00:00"
    }
    ev_t = {
        "event_id": f"ev_date_t_{uuid.uuid4().hex[:6]}",
        "device_id": dev_id,
        "user_id": "date_test_user",
        "timestamp": "2026-10-12T10:00:00.000000+00:00",
        "event_type": "APPLICATION_START",
        "features": {"process_name": "calc.exe", "is_test_event": False},
        "risk_score": 5.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": "2026-10-12T10:00:00.000000+00:00"
    }
    db.save_event(ev_y)
    db.save_event(ev_t)

    # Query Yesterday (2026-10-11)
    res_y = client.get("/api/telemetry/events?date=2026-10-11&client_tz_offset=-330&limit=20")
    assert res_y.status_code == 200
    data_y = res_y.json()
    assert data_y["total"] > 0
    assert len(data_y["events"]) > 0

    # Verify all returned events fall on 2026-10-11 in client local timezone (+330 min)
    for ev in data_y["events"]:
        ts_str = ev.get("timestamp") or ev.get("created_at")
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        local_dt = dt + timedelta(minutes=330)
        assert local_dt.strftime("%Y-%m-%d") == "2026-10-11"

    # Query Today (2026-10-12)
    res_t = client.get("/api/telemetry/events?date=2026-10-12&client_tz_offset=-330&limit=20")
    assert res_t.status_code == 200
    data_t = res_t.json()
    assert data_t["total"] > 0
    for ev in data_t["events"]:
        ts_str = ev.get("timestamp") or ev.get("created_at")
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        local_dt = dt + timedelta(minutes=330)
        assert local_dt.strftime("%Y-%m-%d") == "2026-10-12"


def test_date_query_empty_date_returns_zero_not_today(client):
    """A date without records must return 0 records and NOT fall back to today's records."""
    res = client.get("/api/telemetry/events?date=2026-01-01&client_tz_offset=-330")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 0
    assert data["events"] == []


def test_date_query_timezone_midnight_boundary(client):
    """Test events spanning midnight boundary across local and UTC timezones."""
    dev_id = f"DEV-TZ-{uuid.uuid4().hex[:6]}"

    # Event 1: In local IST (+05:30), 2026-10-11 23:59:30 is UTC 2026-10-11 18:29:30
    ev1_id = f"ev_midnight_1_{uuid.uuid4().hex[:6]}"
    ev1 = {
        "event_id": ev1_id,
        "device_id": dev_id,
        "user_id": "tz_test_user",
        "timestamp": "2026-10-11T18:29:30.000000+00:00",
        "event_type": "APPLICATION_START",
        "features": {"process_name": "app1.exe", "is_test_event": False},
        "risk_score": 5.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": "2026-10-11T18:29:30.000000+00:00"
    }

    # Event 2: In local IST (+05:30), 2026-10-12 00:00:30 is UTC 2026-10-11 18:30:30
    ev2_id = f"ev_midnight_2_{uuid.uuid4().hex[:6]}"
    ev2 = {
        "event_id": ev2_id,
        "device_id": dev_id,
        "user_id": "tz_test_user",
        "timestamp": "2026-10-11T18:30:30.000000+00:00",
        "event_type": "APPLICATION_START",
        "features": {"process_name": "app2.exe", "is_test_event": False},
        "risk_score": 5.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": "2026-10-11T18:30:30.000000+00:00"
    }

    db.save_event(ev1)
    db.save_event(ev2)

    # Query for 2026-10-11 with IST offset (-330)
    res_11 = client.get(f"/api/telemetry/events?device_id={dev_id}&date=2026-10-11&client_tz_offset=-330")
    data_11 = res_11.json()
    assert data_11["total"] == 1
    assert data_11["events"][0]["event_id"] == ev1_id

    # Query for 2026-10-12 with IST offset (-330)
    res_12 = client.get(f"/api/telemetry/events?device_id={dev_id}&date=2026-10-12&client_tz_offset=-330")
    data_12 = res_12.json()
    assert data_12["total"] == 1
    assert data_12["events"][0]["event_id"] == ev2_id


def test_device_isolation_in_events_query(client):
    """Events from Device A must never appear in Device B queries."""
    dev_a = f"DEV-ISO-A-{uuid.uuid4().hex[:6]}"
    dev_b = f"DEV-ISO-B-{uuid.uuid4().hex[:6]}"

    ev_a = {
        "event_id": f"ev_a_{uuid.uuid4().hex[:6]}",
        "device_id": dev_a,
        "user_id": "user_a",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "PROCESS_START",
        "features": {"process_name": "notepad.exe", "is_test_event": False},
        "risk_score": 10.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(ev_a)

    # Query for Device B
    res_b = client.get(f"/api/telemetry/events?device_id={dev_b}")
    assert res_b.json()["total"] == 0

    # Query for Device A
    res_a = client.get(f"/api/telemetry/events?device_id={dev_a}")
    assert res_a.json()["total"] == 1
    assert res_a.json()["events"][0]["event_id"] == ev_a["event_id"]


def test_test_event_isolation_from_real_activities(client):
    """Test events must never leak into real activities."""
    dev_id = f"DEV-TEST-ISO-{uuid.uuid4().hex[:6]}"
    test_ev = {
        "event_id": f"ev_test_{uuid.uuid4().hex[:6]}",
        "device_id": dev_id,
        "user_id": "test_user",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "TEST_DIAGNOSTIC",
        "features": {"process_name": "test.exe", "is_test_event": True},
        "detection_source": "TEST_ENDPOINT",
        "risk_score": 90.0,
        "sync_status": "SYNCHRONIZED",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(test_ev)

    res = client.get(f"/api/telemetry/events?device_id={dev_id}&exclude_test=true")
    assert res.json()["total"] == 0


def test_home_protection_status_values_and_states(client):
    """Verify that /api/device/status returns clear, non-random security postures."""
    res = client.get("/api/device/status")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] in (
        "PROTECTED — NO KNOWN THREAT",
        "THREAT DETECTED",
        "SUSPICIOUS ACTIVITY",
        "UNKNOWN / CHECK FAILED",
        "MONITORING OFFLINE",
        "OFFLINE — MONITORING LOCALLY"
    )
    assert "status_key" in data
    assert "reason" in data
    assert "monitoring_active" in data
    assert "is_online" in data
    assert "checked_at" in data
    assert "recent_activities" in data


def test_controlled_protection_test_endpoint_isolated(client):
    """Test Protection button endpoint runs cleanly without altering genuine incident counts."""
    # Count genuine incidents before
    inc_before = len(db.get_incidents())

    res = client.post("/api/protection/test")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "PASS"
    assert data["outcome"] in ("SAFE", "DANGEROUS", "SUSPICIOUS", "UNKNOWN")
    assert data["is_test_event"] is True
    assert len(data["subsystems_verified"]) == 4

    # Incident count must not have changed
    inc_after = len(db.get_incidents())
    assert inc_after == inc_before
