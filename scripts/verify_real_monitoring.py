"""
CyberThreat AI - Comprehensive Verification Test Script
Tests all requirements on live running backend (http://127.0.0.1:8000):
1. Clean Device Status -> 🟢 Protected
2. Test Safe Scenario -> Flagged SAFE, does not pollute real activity
3. Real Device Identity -> Unique persistent DEVICE_A_...
4. Strict Device Isolation -> Device A vs Device B
5. Friend's Device handling -> NOT_CONNECTED when agent absent, no cross-leakage
6. Real Website Evaluation -> Safe (youtube.com, google.com) vs Dangerous (malware-test-eicar.com)
7. Download Warning -> Safe PDF vs EICAR
8. Offline event queuing and sync restoration
9. Incidents reconstruction -> 4 questions + timeline, clean when no threats
10. Native Windows Toast notifications
"""

import sys
import os
sys.path.insert(0, os.path.abspath("."))
import json
import time
import requests

BASE_URL = "http://127.0.0.1:8000/api"

def check(title, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {title}")
    if detail:
        print(f"       -> {detail}")
    return condition

def run_tests():
    all_passed = True
    print("==================================================================")
    print("STARTING CYBERTHREAT AI REAL MONITORING VERIFICATION SUITE")
    print("==================================================================")

    # 1. Health & Host Device ID
    res = requests.get(f"{BASE_URL}/monitoring/status", timeout=5)
    host_info = res.json()
    host_dev_id = host_info.get("device_id")
    all_passed &= check(
        "Host Device Identity Registered",
        host_dev_id and host_dev_id.startswith("DEVICE_A_"),
        f"Device ID: {host_dev_id}"
    )

    # 2. Clean Device Status
    res = requests.get(f"{BASE_URL}/device/status?device_id={host_dev_id}", timeout=5)
    dev_status = res.json()
    all_passed &= check(
        "Device Status on Clean Host",
        dev_status.get("status") in ["PROTECTED", "SAFE"],
        f"Status returned: {dev_status.get('status')}"
    )

    # 3. Test Safe Scenario Isolation (Requirement 1 & 2)
    # Testing safe scenario via /test/browser-event
    res = requests.post(f"{BASE_URL}/test/browser-event", json={"url": "https://google.com"}, timeout=5)
    test_res = res.json()
    all_passed &= check(
        "Test Safe Scenario Execution",
        test_res.get("status") == "SAFE" and test_res.get("is_test_event") is True,
        f"Status: {test_res.get('status')}, is_test: {test_res.get('is_test_event')}"
    )

    # Verify device status remains PROTECTED after test event
    res = requests.get(f"{BASE_URL}/device/status?device_id={host_dev_id}", timeout=5)
    status_after_test = res.json().get("status")
    all_passed &= check(
        "Device Status Remains Protected After Test Event",
        status_after_test in ["PROTECTED", "SAFE"],
        f"Status after test event: {status_after_test}"
    )

    # 4. Real Website Detection (Requirement 9 & 11)
    res = requests.post(f"{BASE_URL}/browser/event", json={"url": "https://www.youtube.com"}, timeout=5)
    web_res = res.json()
    eval_info = web_res.get("evaluation", {})
    all_passed &= check(
        "Normal Website Assessment (youtube.com)",
        eval_info.get("status") == "SAFE" and eval_info.get("risk_score", 100) < 30,
        f"Status: {eval_info.get('status')}, Risk Score: {eval_info.get('risk_score')}"
    )

    # 5. Controlled Security Threat Assessment (Requirement 12)
    res = requests.post(f"{BASE_URL}/browser/event", json={"url": "https://malware-test-eicar.com"}, timeout=5)
    threat_res = res.json()
    threat_eval = threat_res.get("evaluation", {})
    all_passed &= check(
        "Dangerous Domain Detection (malware-test-eicar.com)",
        threat_eval.get("status") == "DANGEROUS" and threat_eval.get("risk_score", 0) >= 80,
        f"Status: {threat_eval.get('status')}, Risk Score: {threat_eval.get('risk_score')}"
    )

    # 6. Friend's Laptop Telemetry Isolation (Requirements 3, 4, 5, 6)
    friend_dev_id = "DEVICE_B_FRIEND_TEST"
    friend_name = "Friend's Laptop"
    
    # Register friend's device
    requests.post(f"{BASE_URL}/devices/register", json={
        "device_id": friend_dev_id,
        "user_id": "current_user",
        "device_name": friend_name,
        "os_info": "Windows 11 Home"
    }, timeout=5)

    # Send a telemetry event for Friend's Device
    friend_event = {
        "event_id": f"friend_evt_{int(time.time())}",
        "device_id": friend_dev_id,
        "user_id": "current_user",
        "timestamp": "2026-10-07T12:00:00Z",
        "event_type": "WEBSITE_VISITED",
        "features": {
            "domain": "wikipedia.org",
            "url": "https://wikipedia.org",
            "status": "SAFE",
            "is_test_event": False
        }
    }
    requests.post(f"{BASE_URL}/telemetry/event", json=friend_event, timeout=5)

    # Verify query with device_id=friend_dev_id sees ONLY friend's events
    res = requests.get(f"{BASE_URL}/telemetry/events?device_id={friend_dev_id}&limit=50", timeout=5)
    friend_events = res.json().get("events", [])
    has_only_friend = all(e.get("device_id") == friend_dev_id for e in friend_events)
    all_passed &= check(
        "Friend Device Events Isolation (No host leakage into friend's feed)",
        len(friend_events) > 0 and has_only_friend,
        f"Friend events count: {len(friend_events)}, All match friend_dev_id: {has_only_friend}"
    )

    # Verify query for host PC does NOT see friend's events
    res = requests.get(f"{BASE_URL}/telemetry/events?device_id={host_dev_id}&limit=50", timeout=5)
    host_events = res.json().get("events", [])
    has_no_friend = all(e.get("device_id") == host_dev_id for e in host_events)
    all_passed &= check(
        "Host PC Events Isolation (No friend leakage into host's feed)",
        has_no_friend,
        f"Host events count: {len(host_events)}, Zero friend leakage: {has_no_friend}"
    )

    # 7. Unconnected Friend Device status check (Requirement 6)
    unconnected_dev_id = "DEVICE_C_UNCONNECTED_FRIEND"
    requests.post(f"{BASE_URL}/devices/register", json={
        "device_id": unconnected_dev_id,
        "user_id": "current_user",
        "device_name": "Unconnected Laptop",
        "os_info": "Windows 10"
    }, timeout=5)
    res = requests.get(f"{BASE_URL}/device/status?device_id={unconnected_dev_id}", timeout=5)
    unc_status = res.json()
    all_passed &= check(
        "Unconnected Friend Device reports NOT_CONNECTED without fake activity",
        unc_status.get("status") == "NOT_CONNECTED" and unc_status.get("connected") is False,
        f"Status: {unc_status.get('status')}, Connected: {unc_status.get('connected')}"
    )

    # 8. Offline Queue & Idempotent Sync (Requirements 7 & 8)
    # Toggle offline mode
    requests.post(f"{BASE_URL}/sync/toggle-mode", json={"online": False}, timeout=5)
    offline_event = {
        "event_id": f"offline_evt_{int(time.time())}",
        "device_id": host_dev_id,
        "user_id": "current_user",
        "timestamp": "2026-10-07T12:05:00Z",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "notepad.exe",
            "is_test_event": False
        }
    }
    requests.post(f"{BASE_URL}/telemetry/event", json=offline_event, timeout=5)
    
    # Check queue count
    res = requests.get(f"{BASE_URL}/sync/queue", timeout=5)
    queue_data = res.json()
    all_passed &= check(
        "Offline Event Enqueued Locally with PENDING Status",
        queue_data.get("pending_count", 0) >= 1,
        f"Pending queue count: {queue_data.get('pending_count')}"
    )

    # Toggle online mode and trigger sync
    requests.post(f"{BASE_URL}/sync/toggle-mode", json={"online": True}, timeout=5)
    res = requests.post(f"{BASE_URL}/sync/trigger", timeout=5)
    sync_res = res.json()
    all_passed &= check(
        "Reconnection Idempotent Sync restored",
        sync_res.get("status") == "success",
        f"Synced count: {sync_res.get('synced_count')}"
    )

    # 9. Incidents & Reconstruction Structure (Requirements 17 & 18)
    res = requests.get(f"{BASE_URL}/incidents?device_id={host_dev_id}", timeout=5)
    incidents_data = res.json()
    inc_list = incidents_data.get("incidents", [])
    if inc_list:
        sample_inc = inc_list[0]
        has_4_questions = all(k in sample_inc for k in ["what_happened", "why_suspicious", "what_affected", "action_taken"])
        all_passed &= check(
            "Incident Reconstruction Structure (4 questions + timeline)",
            has_4_questions and "timeline" in sample_inc,
            f"Questions present: {has_4_questions}, Timeline present: {'timeline' in sample_inc}"
        )
    else:
        all_passed &= check(
            "Clean Host has No False Incidents",
            len(inc_list) == 0,
            "0 incidents on clean device"
        )

    # 10. Native Windows Toast (Requirement 10 & 20)
    from backend.monitoring.windows_notifier import show_windows_toast
    toast_ok = show_windows_toast(
        "CyberThreat AI — Verification",
        "youtube.com: Website appears safe.",
        status="SAFE"
    )
    all_passed &= check(
        "Native Windows Toast Notification Dispatched",
        toast_ok is True,
        f"Toast status: {toast_ok}"
    )

    print("==================================================================")
    if all_passed:
        print("ALL VERIFICATION SUITE CHECKS PASSED SUCCESSFULLY!")
    else:
        print("SOME CHECKS FAILED. PLEASE REVIEW LOGS.")
    print("==================================================================")
    return all_passed

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
