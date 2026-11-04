"""
CyberThreat AI - Comprehensive Verification Test Suite.
Validates all requirements across Phases 1 - 11:
- Test A: Account and Physical Device Isolation & Prevention of Silent Ownership Transfer
- Test B: Activities Pipeline, Date Filtering (Today, Yesterday, Custom, Range) and Chronological Sorting
- Test C: Offline Activity Collection, SQLite Persistence, and Idempotent Cloud Sync
- Test D: Chrome Extension Gmail & Browser Threat Detection Endpoints
- Test E: Health Metrics and Collector State Tracking
"""

import os
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.database.db import DatabaseManager
from backend.monitoring.hardware_id import get_physical_hardware_id
from backend.main import app, services


@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = DatabaseManager(db_path=path)
    yield db
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ==============================================================================
# TEST A: Account and Physical Device Isolation
# ==============================================================================
def test_physical_device_id_format():
    """Verify hardware ID is persistent and formatted with DEV_ prefix."""
    hw_id = get_physical_hardware_id()
    assert hw_id.startswith("DEV_")
    assert len(hw_id) >= 16


def test_device_ownership_isolation_and_no_silent_transfer(test_db):
    """
    Account A enrolls Laptop A (Device A).
    Account B enrolls Laptop B (Device B).
    Account B cannot silently take over Device A; raises ValueError.
    """
    dev_a = "DEV_HW_AAAA11112222"
    dev_b = "DEV_HW_BBBB33334444"
    user_a = "user_a_alice@corp.com"
    user_b = "user_b_bob@corp.com"

    # Enroll Device A to User A
    res_a = test_db.register_device(dev_a, user_a, "Alice-Laptop", "Windows 11")
    assert res_a["user_id"] == user_a
    assert res_a["device_id"] == dev_a

    # Enroll Device B to User B
    res_b = test_db.register_device(dev_b, user_b, "Bob-Laptop", "Windows 11")
    assert res_b["user_id"] == user_b
    assert res_b["device_id"] == dev_b

    # User B attempts to register Device A -> MUST raise ValueError (no silent transfer)
    with pytest.raises(ValueError, match="already enrolled under another account"):
        test_db.register_device(dev_a, user_b, "Bob-Impostor", "Windows 11")

    # Devices list for User A only returns Device A
    devices_a = test_db.get_devices_by_user(user_a)
    assert len(devices_a) == 1
    assert devices_a[0]["device_id"] == dev_a

    # Devices list for User B only returns Device B
    devices_b = test_db.get_devices_by_user(user_b)
    assert len(devices_b) == 1
    assert devices_b[0]["device_id"] == dev_b


def test_device_removal_permission(test_db):
    """Removing a device requires ownership matching user_id."""
    dev_a = "DEV_HW_AAAA11112222"
    user_a = "user_a@corp.com"
    user_b = "user_b@corp.com"

    test_db.register_device(dev_a, user_a, "Alice-Laptop", "Windows 11")

    # User B attempting to remove User A's device must raise PermissionError
    with pytest.raises(PermissionError):
        test_db.remove_device(dev_a, user_b)

    # User A removing own device succeeds
    res = test_db.remove_device(dev_a, user_a)
    assert res["success"] is True
    assert test_db.get_device(dev_a) is None


# ==============================================================================
# TEST B: Activities Pipeline, Date Filtering & Chronological Sorting
# ==============================================================================
def test_activities_date_filtering_and_sorting(test_db):
    """Verify Today, Yesterday, Custom Date, and Range filtering with sorting."""
    now = datetime.now(timezone.utc)
    today_iso = now.isoformat()
    yesterday_iso = (now - timedelta(days=1)).isoformat()
    two_days_ago_iso = (now - timedelta(days=2)).isoformat()

    dev_id = "DEV_HW_TEST12345678"
    user_id = "analyst@cyberthreat.ai"

    # Event 1: Today - Process Start
    ev_today = {
        "event_id": "EVT_TODAY_01",
        "user_id": user_id,
        "device_id": dev_id,
        "event_type": "PROCESS_START",
        "timestamp": today_iso,
        "risk_score": 15.0,
        "features": {"process_name": "chrome.exe", "activity_category": "Apps"}
    }
    # Event 2: Yesterday - Website Visit
    ev_yesterday = {
        "event_id": "EVT_YEST_01",
        "user_id": user_id,
        "device_id": dev_id,
        "event_type": "WEBSITE_OPENED",
        "timestamp": yesterday_iso,
        "risk_score": 20.0,
        "features": {"domain": "github.com", "activity_category": "Browser"}
    }
    # Event 3: Two Days Ago - System Event
    ev_two_days_ago = {
        "event_id": "EVT_PAST_01",
        "user_id": user_id,
        "device_id": dev_id,
        "event_type": "SYSTEM_LOGON",
        "timestamp": two_days_ago_iso,
        "risk_score": 5.0,
        "features": {"logon_type": "Interactive", "activity_category": "System"}
    }

    test_db.save_event(ev_today)
    test_db.save_event(ev_yesterday)
    test_db.save_event(ev_two_days_ago)

    # 1. Date filter: Today's date string
    today_date_str = now.strftime("%Y-%m-%d")
    res_today = test_db.get_events(date=today_date_str, user_id=user_id)
    assert any(e["event_id"] == "EVT_TODAY_01" for e in res_today)
    assert not any(e["event_id"] == "EVT_YEST_01" for e in res_today)

    # 2. Date filter: Yesterday's date string
    yesterday_date_str = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    res_yest = test_db.get_events(date=yesterday_date_str, user_id=user_id)
    assert any(e["event_id"] == "EVT_YEST_01" for e in res_yest)
    assert not any(e["event_id"] == "EVT_TODAY_01" for e in res_yest)

    # 3. Date Range filter: from 2 days ago to yesterday
    past_date_str = (now - timedelta(days=2)).strftime("%Y-%m-%d")
    res_range = test_db.get_events(start_date=past_date_str, end_date=yesterday_date_str, user_id=user_id)
    ids_in_range = [e["event_id"] for e in res_range]
    assert "EVT_PAST_01" in ids_in_range
    assert "EVT_YEST_01" in ids_in_range
    assert "EVT_TODAY_01" not in ids_in_range

    # 4. Chronological sorting
    all_events = test_db.get_events(user_id=user_id, limit=10)
    timestamps = [e["timestamp"] for e in all_events]
    # Default is DESC (newest first)
    assert timestamps == sorted(timestamps, reverse=True)


# ==============================================================================
# TEST C: Offline Activity Collection, SQLite Persistence & Idempotent Sync
# ==============================================================================
def test_offline_persistence_and_idempotent_sync(test_db):
    """
    Offline events are saved to SQLite with PENDING status, enqueued in sync_queue.
    Reconnection synchronizes idempotently without duplicating records.
    """
    dev_id = "DEV_HW_OFFLINE_TEST"
    user_id = "user_offline@local"

    event_id = "EVT_OFFLINE_DOC_SAVE"
    offline_event = {
        "event_id": event_id,
        "user_id": user_id,
        "device_id": dev_id,
        "event_type": "FILE_MODIFIED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sync_status": "PENDING",
        "features": {
            "activity_domain": "OFFLINE",
            "file_name": "Quarterly_Financials.docx"
        }
    }

    # Save to SQLite and enqueue
    test_db.save_event(offline_event)
    test_db.enqueue_sync(event_id, offline_event, device_id=dev_id)

    # Verify persistent retrieval from SQLite while offline
    stored_events = test_db.get_events(user_id=user_id, exclude_test=False)
    stored = next((e for e in stored_events if e["event_id"] == event_id), None)
    assert stored is not None
    assert stored["event_id"] == event_id
    assert stored["sync_status"] == "PENDING"

    # Check pending sync queue
    pending = test_db.get_pending_sync(limit=10)
    assert any(item["event_id"] == event_id for item in pending)

    # Emulate cloud acknowledgment: update sync status
    test_db.update_event_sync_status(event_id, "SYNCHRONIZED")
    test_db.update_sync_status(event_id, "SYNCHRONIZED")

    # Verify updated status
    updated_events = test_db.get_events(user_id=user_id, exclude_test=False)
    updated = next((e for e in updated_events if e["event_id"] == event_id), None)
    assert updated is not None
    assert updated["sync_status"] == "SYNCHRONIZED"

    # Idempotent re-submission: saving existing event_id with ON CONFLICT DO UPDATE
    test_db.save_event(offline_event)
    count = test_db.get_events_count()
    # Count should remain 1 (no duplicate row inserted)
    all_evs = test_db.get_events(user_id=user_id, exclude_test=False)
    assert len([e for e in all_evs if e["event_id"] == event_id]) == 1


# ==============================================================================
# TEST D: Chrome Extension Gmail & Browser Threat Detection Endpoints
# ==============================================================================
def test_chrome_browser_event_endpoint_safe_and_phishing(client):
    """Verify /api/browser/event accepts Chrome extension events and evaluates threats."""
    dev_id = get_physical_hardware_id()

    # 1. Normal safe browsing event
    safe_payload = {
        "device_id": dev_id,
        "url": "https://www.wikipedia.org/wiki/Computer_security",
        "page_title": "Computer security - Wikipedia",
        "browser_event_type": "BROWSER_NAVIGATION"
    }
    res_safe = client.post("/api/browser/event", json=safe_payload)
    assert res_safe.status_code == 200
    safe_data = res_safe.json()
    assert safe_data["status"] in ("SAFE", "INFO", "NO KNOWN THREAT", "UNVERIFIED")

    # 2. Suspicious Gmail inspection event with phishing indicators
    phishing_payload = {
        "device_id": dev_id,
        "url": "https://mail.google.com/mail/u/0/#inbox/FMfcgzGxT...",
        "page_title": "URGENT: Verify your account immediately",
        "browser_event_type": "GMAIL_INSPECTION",
        "email_threat_indicators": [
            "Spoofed sender: paypal-support@gmail.com claiming paypal.com",
            "Urgent call-to-action requesting credentials",
            "Deceptive link target: http://192.168.1.100/login.php"
        ],
        "verdict_override": "DANGER",
        "reasons_override": ["High-confidence Gmail phishing attempt with credential harvesting link"]
    }
    res_phish = client.post("/api/browser/event", json=phishing_payload)
    assert res_phish.status_code == 200
    phish_data = res_phish.json()
    assert phish_data["status"] == "DANGER"
    assert phish_data["evaluation"]["risk_score"] >= 70
    assert "High-confidence Gmail phishing attempt" in phish_data["reasons"][0]


# ==============================================================================
# TEST E: Monitoring Health Metrics & Accurate Collector States
# ==============================================================================
def test_monitoring_health_metrics_endpoint(client):
    """Verify /api/monitoring/health returns all Phase 5 required health metrics."""
    res = client.get("/api/monitoring/health")
    assert res.status_code == 200
    metrics = res.json()

    required_fields = [
        "events_captured_total",
        "events_persisted_total",
        "events_failed_total",
        "events_dropped_total",
        "collector_heartbeat_timestamp",
        "collector_uptime_seconds",
        "collector_error_total",
        "sqlite_write_latency",
        "pending_sync_queue_size",
        "cloud_sync_latency",
        "duplicate_events_prevented_total",
        "last_successful_event_timestamp",
        "status"
    ]

    for field in required_fields:
        assert field in metrics, f"Missing required health metric: {field}"

    # Collector state should be one of the specified accurate states
    valid_states = [
        "Active",
        "Inactive",
        "Permission Required",
        "Waiting for Events",
        "Offline Collection Active",
        "Sync Pending",
        "Error"
    ]
    assert metrics["status"] in valid_states
