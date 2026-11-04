import pytest
import uuid
from datetime import datetime, timezone
from backend.monitoring.process_monitor import ProcessMonitor
from backend.monitoring.file_monitor import FileMonitor
from backend.monitoring.network_monitor import NetworkMonitor
from backend.monitoring.engine import RealSystemMonitor
from backend.database.db import DatabaseManager
from backend.sync.engine import SyncEngine

@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_stage5.db"
    return DatabaseManager(db_path=str(db_file))

def test_whole_computer_collectors():
    """Validates that real Windows host monitors initialize and evaluate telemetry without throwing."""
    # 1. Process Monitor
    pm = ProcessMonitor()
    live_procs = pm.scan_running_processes(max_procs=10)
    assert isinstance(live_procs, list)
    assert len(live_procs) > 0
    assert "display_name" in live_procs[0]
    assert "status" in live_procs[0]
    assert "risk_score" in live_procs[0]

    # Process evaluation of a test process
    eval_proc = pm.evaluate_process({"name": "test_app.exe", "exe": "C:\\Program Files\\test_app.exe", "cmdline": ["test_app.exe"]})
    assert eval_proc["display_name"] == "Test_app"
    assert eval_proc["status"] == "INFO"

    # 2. File Monitor
    fm = FileMonitor()
    assert len(fm.watch_dirs) > 0
    # Evaluate a benign synthetic path
    eval_f = fm.evaluate_file("C:\\nonexistent_test_sample.txt")
    assert eval_f["status"] == "UNKNOWN"

    # 3. Network Monitor
    nm = NetworkMonitor()
    assert hasattr(nm, "_seen_conns")
    assert nm._is_private_ip("192.168.1.1") is True
    assert nm._is_private_ip("8.8.8.8") is False

def test_offline_monitoring_and_idempotent_sync(test_db):
    """Validates that offline events are preserved in SQLite and synced idempotently."""
    sync_engine = SyncEngine(db_manager=test_db)
    
    # Simulate network disconnect
    sync_engine.set_connectivity(False)
    assert sync_engine.is_online is False

    # Simulate 3 offline host events
    event_ids = [f"evt_offline_{i}" for i in range(3)]
    for eid in event_ids:
        ev = {
            "event_id": eid,
            "device_id": "DEVICE_STAGE5_TEST",
            "user_id": "local_user",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PROCESS_START",
            "features": {"process_name": "cmd.exe", "display_name": "Command Prompt"},
            "risk_score": 10.0,
            "anomaly_score": 5.0,
            "behavioral_drift": 0.0,
            "detection_source": "REAL_PROCESS_MONITOR",
            "sync_status": "PENDING"
        }
        # Save to local SQLite events table
        test_db.save_event(ev)
        # Enqueue for offline sync
        sync_engine.queue_offline_event(ev)

    # Verify pending queue count in SQLite
    assert test_db.get_pending_sync_count() == 3

    # Verify events are immediately queryable in SQLite history while offline
    stored_events = test_db.get_events(device_id="DEVICE_STAGE5_TEST")
    assert len(stored_events) == 3
    assert all(e["sync_status"] == "PENDING" for e in stored_events)

    # Re-establish connectivity
    sync_engine.set_connectivity(True)
    assert sync_engine.is_online is True

    # Sync pending queue
    sync_res = sync_engine.sync_pending_queue()
    assert sync_res["status"] == "success"
    assert sync_res["processed_count"] == 3
    assert test_db.get_pending_sync_count() == 0

    # Test idempotency: re-syncing the same events must NOT create duplicates
    dup_res = sync_engine.process_sync_batch(stored_events)
    assert dup_res["duplicate_count"] == 3
    assert dup_res["processed_count"] == 0

    # Confirm events in database still equals 3 (no duplication)
    final_events = test_db.get_events(device_id="DEVICE_STAGE5_TEST")
    assert len(final_events) == 3
