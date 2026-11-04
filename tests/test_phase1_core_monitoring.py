"""
Phase 1 Verification Test Suite: Core Monitoring System & Activity History.

Validates the Phase 1 Success Criteria:
1. Capture supported Windows online and offline activities (processes, files, network, docs).
2. Store every event in SQLite immediately, even without internet.
3. Display historical events using Today, Yesterday and Custom Date filters with timezone boundaries.
4. Preserve original timestamps and device IDs throughout offline-online cycles.
5. Synchronize pending events after reconnection without duplicates (idempotency).
6. Strict separation of test events from genuine user activities.
7. Offline Simulation: Disconnect, generate activities, reconnect, verify all preserved and displayed.
"""

import pytest
import uuid
import time
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from backend.database.db import DatabaseManager
from backend.sync.engine import SyncEngine
from backend.monitoring.process_monitor import ProcessMonitor
from backend.monitoring.file_monitor import FileMonitor
from backend.monitoring.network_monitor import NetworkMonitor
from backend.monitoring.engine import RealSystemMonitor


@pytest.fixture
def temp_db(tmp_path):
    """Provides an isolated clean SQLite database for testing."""
    db_file = tmp_path / "test_phase1.db"
    db = DatabaseManager(db_path=str(db_file))
    return db


def test_immediate_sqlite_storage_offline(temp_db):
    """Criterion 2: Store every event in SQLite immediately, even without internet."""
    sync_engine = SyncEngine(db_manager=temp_db)
    sync_engine.set_connectivity(False)
    assert not sync_engine.is_online

    dev_id = "DEV_HW_TEST001"
    user_id = "usr_phase1_test"
    temp_db.register_device(device_id=dev_id, user_id=user_id, device_name="Test Laptop")

    # Simulate 3 offline events
    events = [
        {
            "event_id": f"evt_off_{uuid.uuid4().hex[:8]}",
            "device_id": dev_id,
            "user_id": user_id,
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(),
            "event_type": "APPLICATION_START",
            "features": {"process_name": "notepad.exe", "display_name": "Notepad", "activity_category": "Apps"},
            "sync_status": "PENDING",
            "detection_source": "REAL_PROCESS_MONITOR"
        },
        {
            "event_id": f"evt_off_{uuid.uuid4().hex[:8]}",
            "device_id": dev_id,
            "user_id": user_id,
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
            "event_type": "FILE_DOWNLOAD",
            "features": {"file_name": "report.pdf", "activity_category": "Downloads"},
            "sync_status": "PENDING",
            "detection_source": "REAL_FILE_MONITOR"
        },
        {
            "event_id": f"evt_off_{uuid.uuid4().hex[:8]}",
            "device_id": dev_id,
            "user_id": user_id,
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            "event_type": "NETWORK_CONNECTION",
            "features": {"remote_ip": "192.168.1.1", "remote_port": 80, "activity_category": "Network"},
            "sync_status": "PENDING",
            "detection_source": "REAL_NETWORK_MONITOR"
        }
    ]

    # Save immediately to SQLite and queue
    for ev in events:
        temp_db.enqueue_sync(ev["event_id"], ev, device_id=dev_id)
        saved = temp_db.save_event(ev)
        assert saved is True

    # Verify all 3 events are immediately queryable in SQLite while offline
    stored = temp_db.get_events(device_id=dev_id, exclude_test=True)
    assert len(stored) == 3
    assert all(e["sync_status"] == "PENDING" for e in stored)
    assert temp_db.get_pending_sync_count() == 3


def test_date_filters_today_yesterday_custom(temp_db):
    """Criterion 3: Display historical events using Today, Yesterday and Custom Date filters."""
    dev_id = "DEV_HW_DATE01"
    user_id = "usr_date_test"
    temp_db.register_device(device_id=dev_id, user_id=user_id, device_name="Date Test Laptop")

    # Assume client is in IST (UTC +5:30 -> offset = -330)
    client_offset = -330
    local_now = datetime.now(timezone.utc) + timedelta(minutes=330)
    today_str = local_now.strftime("%Y-%m-%d")
    yesterday_str = (local_now - timedelta(days=1)).strftime("%Y-%m-%d")
    two_days_ago_str = (local_now - timedelta(days=2)).strftime("%Y-%m-%d")

    # Create event for TODAY in local time
    ev_today = {
        "event_id": "evt_d_today",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "APPLICATION_START",
        "features": {"process_name": "chrome.exe", "activity_category": "Apps"},
        "detection_source": "REAL_PROCESS_MONITOR"
    }

    # Create event for YESTERDAY in local time (24h ago)
    ev_yesterday = {
        "event_id": "evt_d_yesterday",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),
        "event_type": "FILE_DOWNLOAD",
        "features": {"file_name": "yesterday.docx", "activity_category": "Downloads"},
        "detection_source": "REAL_FILE_MONITOR"
    }

    # Create event for 2 DAYS AGO in local time (48h ago)
    ev_two_days = {
        "event_id": "evt_d_twodays",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
        "event_type": "WEBSITE_OPENED",
        "features": {"domain": "github.com", "activity_category": "Websites"},
        "detection_source": "CHROME_EXTENSION"
    }

    temp_db.save_event(ev_today)
    temp_db.save_event(ev_yesterday)
    temp_db.save_event(ev_two_days)

    # 1. Filter TODAY
    res_today = temp_db.get_events(device_id=dev_id, date=today_str, client_tz_offset=client_offset)
    assert len(res_today) == 1
    assert res_today[0]["event_id"] == "evt_d_today"

    # 2. Filter YESTERDAY
    res_yesterday = temp_db.get_events(device_id=dev_id, date=yesterday_str, client_tz_offset=client_offset)
    assert len(res_yesterday) == 1
    assert res_yesterday[0]["event_id"] == "evt_d_yesterday"

    # 3. Filter CUSTOM DATE (2 days ago)
    res_custom = temp_db.get_events(device_id=dev_id, date=two_days_ago_str, client_tz_offset=client_offset)
    assert len(res_custom) == 1
    assert res_custom[0]["event_id"] == "evt_d_twodays"

    # 4. Filter NON-EXISTENT DATE returns empty list cleanly
    res_empty = temp_db.get_events(device_id=dev_id, date="2020-01-01", client_tz_offset=client_offset)
    assert len(res_empty) == 0

    # 5. Verify get_date_summary categorizes all days accurately
    summary = temp_db.get_date_summary(device_id=dev_id, client_tz_offset=client_offset)
    assert len(summary) == 3
    dates_found = [s["date"] for s in summary]
    assert today_str in dates_found
    assert yesterday_str in dates_found
    assert two_days_ago_str in dates_found


def test_timestamp_and_device_preservation_and_duplicate_free_sync(temp_db):
    """Criteria 4 & 5: Preserve timestamps and device IDs, synchronize without duplicates."""
    sync_engine = SyncEngine(db_manager=temp_db)
    sync_engine.set_connectivity(False)

    dev_id = "DEV_PRESERVE_001"
    user_id = "usr_preserve"
    original_timestamp = "2026-10-31T14:30:00.123456+00:00"

    event = {
        "event_id": "evt_pres_001",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": original_timestamp,
        "event_type": "APPLICATION_START",
        "features": {"process_name": "wordpad.exe"},
        "sync_status": "PENDING",
        "detection_source": "REAL_PROCESS_MONITOR"
    }

    # Saved offline
    temp_db.enqueue_sync(event["event_id"], event, device_id=dev_id)
    temp_db.save_event(event)

    # Transition to ONLINE and run synchronization
    sync_engine.set_connectivity(True)
    sync_res = sync_engine.sync_pending_queue()
    assert sync_res["status"] == "success"
    assert sync_res["processed_count"] == 1
    assert sync_res["duplicate_count"] == 0

    # Verify event fields: original timestamp and device ID MUST BE PRESERVED
    updated = temp_db.get_event("evt_pres_001")
    assert updated["device_id"] == dev_id
    assert updated["user_id"] == user_id
    assert updated["timestamp"] == original_timestamp
    assert updated["sync_status"] == "SYNCHRONIZED"
    assert updated["synchronized_at"] is not None

    # REPLAY TEST (simulate network glitch where same batch is re-sent)
    replay_res = sync_engine.process_sync_batch([event])
    assert replay_res["duplicate_count"] == 1
    assert replay_res["processed_count"] == 0

    # Verify SQLite still has exactly 1 event (no duplicates created)
    all_events = temp_db.get_events(device_id=dev_id)
    assert len(all_events) == 1


def test_separation_of_test_events_from_genuine_activities(temp_db):
    """Criterion 6: Separate test events from genuine user activities."""
    dev_id = "DEV_SEP_TEST"
    user_id = "usr_sep_test"

    # Genuine activity
    genuine_event = {
        "event_id": "evt_genuine_001",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "APPLICATION_START",
        "features": {"process_name": "code.exe", "display_name": "VS Code", "activity_category": "Apps", "is_test_event": False},
        "detection_source": "REAL_PROCESS_MONITOR"
    }

    # Synthetic / Diagnostic Test Events
    test_event_1 = {
        "event_id": "evt_test_001",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "TEST_APPLICATION",
        "features": {"process_name": "test_runner.exe", "is_test_event": True, "activity_category": "Test"},
        "detection_source": "TEST_ENDPOINT"
    }
    test_event_2 = {
        "event_id": "evt_test_002",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "APPLICATION_START",
        "features": {"process_name": "eicar.exe", "is_test_event": True},
        "detection_source": "DIAGNOSTIC_SUITE"
    }

    temp_db.save_event(genuine_event)
    temp_db.save_event(test_event_1)
    temp_db.save_event(test_event_2)

    # 1. Total rows in raw DB table is 3
    assert temp_db.get_event_count() == 3

    # 2. Activity view query with exclude_test=True MUST return ONLY the genuine event
    clean_events = temp_db.get_events(device_id=dev_id, exclude_test=True)
    assert len(clean_events) == 1
    assert clean_events[0]["event_id"] == "evt_genuine_001"
    assert clean_events[0]["features"]["display_name"] == "VS Code"

    # 3. Activity count with exclude_test=True MUST be 1
    clean_count = temp_db.get_events_count(device_id=dev_id, exclude_test=True)
    assert clean_count == 1

    # 4. Date summary MUST count only the 1 genuine activity
    summary = temp_db.get_date_summary(device_id=dev_id, exclude_test=True)
    assert len(summary) == 1
    assert summary[0]["total"] == 1


def test_full_offline_simulation_success_criteria(temp_db):
    """
    Phase 1 Primary Success Criteria:
    Restart app, disconnect the internet, generate supported activities,
    reconnect, and verify that all events are preserved and displayed.
    """
    sync_engine = SyncEngine(db_manager=temp_db)
    monitor = RealSystemMonitor(db_manager=temp_db)
    dev_id = monitor.device_id
    user_id = "usr_live_sim"
    monitor.bind_enrolled_device(device_id=dev_id, user_id=user_id)

    # STEP 1: Disconnect the internet
    sync_engine.set_connectivity(False)
    assert not sync_engine.is_online

    # Pipeline callback simulating backend/main.py behavior during offline state
    collected_events = []
    def pipeline(ev):
        ev["sync_status"] = "PENDING"
        ev["synchronized_at"] = None
        temp_db.enqueue_sync(ev["event_id"], ev, device_id=dev_id)
        temp_db.save_event(ev)
        collected_events.append(ev)
        return ev

    monitor.set_pipeline_callback(pipeline)

    # STEP 2: Generate supported Windows activities while offline
    # Activity A: Offline process
    p_info = {"pid": 9991, "name": "notepad.exe", "exe": "C:\\Windows\\notepad.exe", "cmdline": ""}
    p_eval = ProcessMonitor.evaluate_process(p_info)
    ev_proc = {
        "event_id": f"evt_p_{uuid.uuid4().hex[:8]}",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=8)).isoformat(),
        "event_type": p_eval["event_type"],
        "features": {
            "process_name": p_eval["name"],
            "display_name": p_eval["display_name"],
            "description": p_eval["description"],
            "activity_category": "Apps"
        },
        "detection_source": "REAL_PROCESS_MONITOR"
    }
    monitor._emit_event(ev_proc)

    # Activity B: Offline download file
    ev_file = {
        "event_id": f"evt_f_{uuid.uuid4().hex[:8]}",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "event_type": "FILE_DOWNLOAD",
        "features": {
            "file_name": "quarterly_budget.xlsx",
            "extension": ".xlsx",
            "file_size": 45000,
            "status": "SAFE",
            "activity_category": "Downloads"
        },
        "detection_source": "REAL_FILE_MONITOR"
    }
    monitor._emit_event(ev_file)

    # Activity C: Network socket
    c_info = {"remote_ip": "1.1.1.1", "remote_port": 443, "process_name": "chrome.exe", "status": "ESTABLISHED"}
    c_eval = NetworkMonitor.evaluate_connection(c_info)
    ev_net = {
        "event_id": f"evt_n_{uuid.uuid4().hex[:8]}",
        "device_id": dev_id,
        "user_id": user_id,
        "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat(),
        "event_type": "NETWORK_CONNECTION",
        "features": {
            "remote_ip": "1.1.1.1",
            "remote_port": 443,
            "display_name": "chrome.exe (1.1.1.1:443)",
            "status": c_eval["threat_status"],
            "activity_category": "Network"
        },
        "detection_source": "REAL_NETWORK_MONITOR"
    }
    monitor._emit_event(ev_net)

    # Verify that all 3 activities were stored in SQLite immediately during offline mode
    assert len(collected_events) == 3
    offline_db_events = temp_db.get_events(device_id=dev_id, exclude_test=True)
    assert len(offline_db_events) == 3
    assert all(e["sync_status"] == "PENDING" for e in offline_db_events)
    assert temp_db.get_pending_sync_count() == 3

    # STEP 3: Reconnect to internet
    sync_engine.set_connectivity(True)
    assert sync_engine.is_online

    # STEP 4: Trigger synchronization after reconnection
    sync_result = sync_engine.sync_pending_queue()
    assert sync_result["status"] == "success"
    assert sync_result["processed_count"] == 3
    assert sync_result["duplicate_count"] == 0

    # STEP 5: Verify that all events are preserved and displayed
    synced_events = temp_db.get_events(device_id=dev_id, exclude_test=True)
    assert len(synced_events) == 3

    # Preserved original timestamps and device IDs
    event_map = {e["event_id"]: e for e in synced_events}
    assert event_map[ev_proc["event_id"]]["timestamp"] == ev_proc["timestamp"]
    assert event_map[ev_file["event_id"]]["timestamp"] == ev_file["timestamp"]
    assert event_map[ev_net["event_id"]]["timestamp"] == ev_net["timestamp"]

    # All transitioned to SYNCHRONIZED without duplicates
    assert all(e["sync_status"] == "SYNCHRONIZED" for e in synced_events)
    assert all(e["synchronized_at"] is not None for e in synced_events)
    assert temp_db.get_pending_sync_count() == 0
