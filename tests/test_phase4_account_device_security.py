"""
Phase 4 Verification: Strengthen Account & Device Security
Tests verify:
1. Persistent Physical Hardware Device ID (DEV_HW_<HEX>) across reboots and calls
2. Account binding & cryptographic device credentials generation
3. Strict Multi-User Isolation: Account A cannot access or manipulate Account B's devices, events, or incidents (403 Forbidden)
4. Add, Rename, Revoke, and Remove Device Lifecycle
5. Chrome Extension pairing and status verification
6. Zero-collection privacy pledge enforcement (no passwords, cookies, session tokens in URLs or stored events)
"""

import pytest
import uuid
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app, services
from backend.monitoring.hardware_id import get_physical_hardware_id
from backend.security.auth import create_access_token

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def db():
    return services["db"]

def test_persistent_hardware_device_id():
    """
    Verify get_physical_hardware_id generates a stable DEV_<HEX> identifier
    consistent across multiple calls.
    """
    id1 = get_physical_hardware_id()
    id2 = get_physical_hardware_id()
    assert id1.startswith("DEV_")
    assert len(id1) >= 10
    assert id1 == id2, "Physical hardware ID must be persistent across calls"

def _create_authenticated_user(db, prefix="user"):
    uid = f"{prefix}_{uuid.uuid4().hex[:6]}"
    email = f"{uid}@cyberthreat.test"
    u = db.create_user(email=email, password="ValidPassword123!", name=prefix.capitalize())
    token = create_access_token(user_id=u["id"], email=u["email"])
    return u, {"Authorization": f"Bearer {token}"}

def test_device_enrollment_and_credentials(client, db):
    """
    Verify device enrollment generates secret device_key and binds to account.
    """
    user, headers = _create_authenticated_user(db, "alice")
    dev_name = "Finance Laptop"
    resp = client.post(
        "/api/devices/enroll",
        json={"device_name": dev_name, "os_info": "Windows 11 Pro"},
        headers=headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    device = data["device"]
    dev_id = device["device_id"]
    dev_key = device["device_key"]
    assert dev_key.startswith("dk_")
    assert len(dev_key) > 20

    # Verify credentials via DB
    assert db.verify_device_credentials(dev_id, dev_key) is True
    assert db.verify_device_credentials(dev_id, "invalid_key_123") is False

def test_multi_user_isolation_strict_403(client, db):
    """
    Verify Account A cannot view, sync, or manipulate Account B's devices or telemetry.
    """
    user_a, headers_a = _create_authenticated_user(db, "alice")
    user_b, headers_b = _create_authenticated_user(db, "bob")

    # Enroll Device B under User B
    resp_b = client.post(
        "/api/devices/enroll",
        json={"device_name": "Bob's Workstation", "os_info": "Windows 11"},
        headers=headers_b
    )
    assert resp_b.status_code == 200
    dev_b_id = resp_b.json()["device"]["device_id"]

    # Enroll Device A under User A
    resp_a = client.post(
        "/api/devices/enroll",
        json={"device_name": "Alice's Laptop", "os_info": "Windows 11"},
        headers=headers_a
    )
    assert resp_a.status_code == 200
    dev_a_id = resp_a.json()["device"]["device_id"]

    # 1. User A tries to view Device B's telemetry events -> 403 Forbidden
    resp_events = client.get(f"/api/telemetry/events?device_id={dev_b_id}", headers=headers_a)
    assert resp_events.status_code == 403
    assert "Access denied" in resp_events.json()["detail"]

    # 2. User A tries to view Device B's incidents -> 403 Forbidden
    resp_inc = client.get(f"/api/incidents?device_id={dev_b_id}", headers=headers_a)
    assert resp_inc.status_code == 403
    assert "Access denied" in resp_inc.json()["detail"]

    # 3. User A tries to rename Device B -> 403 Forbidden
    resp_rename = client.put(f"/api/devices/{dev_b_id}", json={"device_name": "Hacked Name"}, headers=headers_a)
    assert resp_rename.status_code == 403

    # 4. User A tries to revoke Device B -> 403 Forbidden
    resp_revoke = client.post(f"/api/devices/{dev_b_id}/revoke", json={}, headers=headers_a)
    assert resp_revoke.status_code == 403

    # 5. User A tries to remove Device B -> 403 Forbidden
    resp_remove = client.delete(f"/api/devices/{dev_b_id}", headers=headers_a)
    assert resp_remove.status_code == 403

    # 6. User A tries to sync an event claiming it came from Device B -> 403 Forbidden
    now_iso = datetime.now(timezone.utc).isoformat()
    ev_payload = {
        "event_id": f"ev_spoof_{uuid.uuid4().hex[:6]}",
        "device_id": dev_b_id,
        "user_id": user_a["id"],
        "timestamp": now_iso,
        "event_type": "APPLICATION_START",
        "features": {"app_name": "notepad.exe"}
    }
    resp_sync = client.post(
        "/api/sync/offline-batch",
        json={"device_id": dev_b_id, "events": [ev_payload]},
        headers=headers_a
    )
    assert resp_sync.status_code == 403

def test_device_lifecycle_rename_revoke_remove(client, db):
    """
    Verify full lifecycle: Rename, Revoke (blocks new telemetry), and Remove.
    """
    user, headers = _create_authenticated_user(db, "lifecycle")

    # 1. Enroll
    enroll_res = client.post(
        "/api/devices/enroll",
        json={"device_name": "Initial Name", "os_info": "Win11"},
        headers=headers
    ).json()
    dev_id = enroll_res["device"]["device_id"]

    # 2. Rename
    rename_res = client.put(
        f"/api/devices/{dev_id}",
        json={"device_name": "Secured Workstation"},
        headers=headers
    )
    assert rename_res.status_code == 200
    assert rename_res.json()["device_name"] == "Secured Workstation"

    # 3. Revoke
    revoke_res = client.post(f"/api/devices/{dev_id}/revoke", headers=headers)
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "REVOKED"

    # Verify telemetry ingestion is now blocked for revoked device
    post_event = client.post(
        "/api/browser/event",
        json={
            "url": "https://example.com",
            "title": "Example Page",
            "user_id": user["id"],
            "device_id": dev_id
        }
    )
    assert post_event.status_code == 403
    assert "revoked" in post_event.json()["detail"].lower()

    # 4. Remove
    remove_res = client.delete(f"/api/devices/{dev_id}", headers=headers)
    assert remove_res.status_code == 200
    assert remove_res.json()["success"] is True

def test_chrome_extension_pairing_and_privacy_pledge(client, db):
    """
    Verify:
    1. Chrome extension pairing flow
    2. Zero-collection privacy pledge: Sensitive query parameters in URLs (tokens/passwords)
       are redacted and never stored, and forbidden credential fields are dropped.
    """
    user, headers = _create_authenticated_user(db, "privacy")

    # Enroll device
    enroll = client.post("/api/devices/enroll", json={"device_name": "Browser PC"}, headers=headers).json()
    dev_id = enroll["device"]["device_id"]

    # 1. Extension pairing
    pair_res = client.post(
        "/api/extension/pair",
        json={"device_id": dev_id, "user_id": user["id"]},
        headers=headers
    )
    assert pair_res.status_code == 200
    pair_data = pair_res.json()
    assert pair_data["status"] == "paired"
    assert pair_data["pairing_token"].startswith("ext_pair_")

    # Extension status
    status_res = client.get(f"/api/extension/status?device_id={dev_id}")
    assert status_res.status_code == 200
    assert status_res.json()["paired"] is True

    # 2. Zero-collection privacy test: URL with passwords, tokens, auth codes
    sensitive_url = "https://portal.bank.com/dashboard?session=sess_abc123&password=secretPassword999&token=oauth_xyz"
    event_payload = {
        "url": sensitive_url,
        "title": "Banking Dashboard",
        "user_id": user["id"],
        "device_id": dev_id,
        "password": "DO_NOT_STORE_PASSWORD",
        "cookies": ["session=123", "auth=456"],
        "keystrokes": "secret typing string"
    }

    resp = client.post("/api/browser/event", json=event_payload)
    assert resp.status_code == 200

    # Query the stored event from DB
    events = db.get_events(limit=5, device_id=dev_id, exclude_test=False)
    assert len(events) > 0
    stored_ev = events[0]
    features = stored_ev.get("features", {})
    if isinstance(features, str):
        features = json.loads(features)

    # Verify privacy protections:
    # 1. Raw password/keystroke/cookie fields must NOT exist in features
    assert "password" not in features
    assert "cookies" not in features
    assert "keystrokes" not in features

    # 2. The stored URL must have redacted sensitive parameters
    stored_url = features.get("url", "")
    assert "secretPassword999" not in stored_url
    assert "sess_abc123" not in stored_url
    assert "[REDACTED]" in stored_url or "%5BREDACTED%5D" in stored_url

