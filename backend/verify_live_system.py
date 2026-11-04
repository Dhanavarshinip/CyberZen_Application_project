"""
Live Verification Script for CyberThreat AI System.

Tests all live FastAPI endpoints, end-to-end scenario execution,
and offline-to-online sync resiliency.
"""

import time
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000/api"

def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as res:
        return json.loads(res.read().decode("utf-8"))


def http_post(path, data):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as res:
        return json.loads(res.read().decode("utf-8"))

def verify_all():
    print("==================================================")
    print("[*] Verifying Live FastAPI Research Endpoints...")
    print("==================================================")

    # 1. Health check
    health = http_get("/health")
    print(f"[+] /health -> status: {health.get('status')}, ml_model: {health.get('ml_model')}")
    assert health["status"] == "healthy"

    # 2. Dashboard Overview
    overview = http_get("/dashboard/overview")
    print(f"[+] /dashboard/overview -> risk_score: {overview.get('current_risk_score')}, level: {overview.get('risk_level')}, formula: {overview.get('formula')}")
    assert "current_risk_score" in overview

    # 3. Telemetry Event Ingestion
    test_ev = {
        "device_id": "DEV-TEST-VERIFY",
        "user_id": "researcher_alice",
        "event_type": "LOGIN",
        "features": {
            "login_hour": 10,
            "device_id": "DEV-TEST-VERIFY",
            "application": "code_editor"
        }
    }
    ingest_res = http_post("/telemetry/event", test_ev)
    print(f"[+] /telemetry/event -> anomaly_score: {ingest_res.get('anomaly_score')}, drift: {ingest_res.get('behavioral_drift')}, risk_score: {ingest_res.get('risk_score')}")
    assert "anomaly_score" in ingest_res
    assert "risk_score" in ingest_res

    # 4. Knowledge Graph
    graph = http_get("/graph")
    print(f"[+] /graph -> total_nodes: {graph.get('stats', {}).get('total_nodes')}, total_edges: {graph.get('stats', {}).get('total_edges')}")
    assert len(graph.get("nodes", [])) > 0

    # 5. Incidents
    incidents = http_get("/incidents")
    print(f"[+] /incidents -> active incidents count: {incidents.get('total')}")

    # 6. 'What Changed?' Analysis
    wc = http_get("/what-changed/researcher_alice")
    print(f"[+] /what-changed/researcher_alice -> baseline_established: {wc.get('baseline_established')}, summary: {wc.get('summary')[:70]}...")

    # 7. Adaptive Response Recommendation
    resp = http_post("/response/recommend", {"risk_score": 72.5})
    print(f"[+] /response/recommend -> action_type: {resp.get('action_type')}, policy_tier: {resp.get('policy_tier')}")
    assert resp["action_type"] == "REQUIRE_MFA"

    # 8. Grounded AI Investigator
    inv_res = http_post("/investigator/chat", {"query": "Why was this incident suspicious?"})
    print(f"[+] /investigator/chat -> mode: {inv_res.get('mode')}, answer preview: {inv_res.get('answer')[:80]}...")
    assert inv_res["mode"] == "deterministic_fallback"

    # 9. End-to-End Synthetic Scenario Execution
    print("\n==================================================")
    print("[*] Running End-to-End Scenario 6 (Multi-Stage Attack)...")
    print("==================================================")
    scenario_res = http_post("/demo/scenario/scenario_6_multi_stage", {})
    print(f"[+] Scenario: {scenario_res.get('scenario')}")
    print(f"[+] Events Generated & Ingested: {scenario_res.get('events_generated')}")
    print(f"[+] Incidents Reconstructed: {scenario_res.get('reconstructed_incidents')}")
    for idx, ev in enumerate(scenario_res.get("processed_events", []), 1):
        print(f"    Stage {idx}: {ev.get('event_type')} | Anomaly A(t)={ev.get('anomaly_score'):.1f} | Drift B(t)={ev.get('behavioral_drift'):.1f} | Risk R(t)={ev.get('risk_score'):.1f}")

    # 10. Offline Sync & Duplicate Prevention
    print("\n==================================================")
    print("[*] Verifying Offline Synchronization Path...")
    print("==================================================")
    # Set to offline
    off_toggle = http_post("/sync/toggle-mode", {"online": False})
    print(f"[+] Offline Mode Activated -> online: {off_toggle.get('online_mode')}")
    assert off_toggle["online_mode"] is False

    # Ingest event while offline
    offline_event = {
        "event_id": f"OFFLINE_TEST_{int(time.time())}",
        "device_id": "FIELD-LAPTOP-OFFLINE",
        "user_id": "field_analyst",
        "event_type": "NETWORK",
        "features": {"destination": "internal-server.local"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    http_post("/telemetry/event", offline_event)
    
    # Toggle back online to trigger synchronization
    on_toggle = http_post("/sync/toggle-mode", {"online": True})
    print(f"[+] Connection Restored -> Sync Result: {on_toggle.get('sync_result', {}).get('status')}, Processed: {on_toggle.get('sync_result', {}).get('processed_count')}")

    # Verify duplicate prevention
    dup_res = http_post("/sync/offline-batch", {"events": [offline_event], "device_id": "FIELD-LAPTOP-OFFLINE"})
    print(f"[+] Duplicate Check -> Duplicate Count: {dup_res.get('duplicate_count')}, Processed Count: {dup_res.get('processed_count')}")
    assert dup_res["duplicate_count"] == 1
    assert dup_res["processed_count"] == 0

    print("\n==================================================")
    print("[+] All Live Backend Endpoints & Subsystems Successfully Verified!")
    print("==================================================")

if __name__ == "__main__":
    verify_all()
