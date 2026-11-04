"""
Phase 3 Verification: Intelligent Incident Reconstruction & Temporal Knowledge Graph
Tests verify:
1. Full Causal Graph Schema: User -> Device -> Application -> Session -> Network Entity -> Event -> Incident
2. Multi-stage attack chain chronological reconstruction (Phishing -> Download -> Execution -> Egress)
3. Lateral movement analysis & blast radius node categorization (Affected vs Clean instances)
4. Executable Cypher query generation matching PuppyGraph reference design
5. Explainable causal sequence narrative
6. API endpoint GET /api/incidents/{incident_id}/graph
"""

import pytest
import uuid
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app, services
from backend.database.db import DatabaseManager
from backend.knowledge_graph.graph import TemporalKnowledgeGraph
from backend.incident_engine.reconstructor import IncidentReconstructor

@pytest.fixture
def clean_graph():
    return TemporalKnowledgeGraph()

@pytest.fixture
def api_client():
    return TestClient(app)

def test_causal_graph_schema_linkages(clean_graph):
    """
    Verify complete schema linkage:
    User -> Device -> Application -> Session -> Network Entity -> Event -> Incident
    """
    ts = datetime.now(timezone.utc).isoformat()
    ev_id = f"ev_test_{uuid.uuid4().hex[:6]}"
    inc_id = f"INC_TEST_{uuid.uuid4().hex[:6]}"
    user_id = "analyst_alice"
    dev_id = "DEV_WIN11_SEC"
    app_name = "powershell.exe"
    dest = "198.51.100.45"
    sess_id = f"sess_{user_id}_{dev_id}"

    event_payload = {
        "event_id": ev_id,
        "event_type": "SUSPICIOUS_SCRIPT_EXECUTION",
        "timestamp": ts,
        "user_id": user_id,
        "device_id": dev_id,
        "risk_score": 85.0,
        "anomaly_score": 75.0,
        "behavioral_drift": 40.0,
        "features": {
            "app_name": app_name,
            "destination_ip": dest,
            "session_id": sess_id,
            "description": "Base64 encoded command executed via PowerShell connecting to C2 IP"
        }
    }

    clean_graph.ingest_event(event_payload)
    clean_graph.add_incident_node(inc_id, severity="CRITICAL", properties={"title": "C2 Infiltration Test"})
    clean_graph.link_event_to_incident(ev_id, inc_id)

    # 1. Verify all expected nodes are present
    assert clean_graph.graph.has_node(f"user:{user_id}")
    assert clean_graph.graph.has_node(f"device:{dev_id}")
    assert clean_graph.graph.has_node(f"session:{sess_id}")
    assert clean_graph.graph.has_node(f"app:{app_name}")
    assert clean_graph.graph.has_node(f"net:{dest}")
    assert clean_graph.graph.has_node(f"event:{ev_id}")
    assert clean_graph.graph.has_node(f"incident:{inc_id}")

    # 2. Verify relational edges
    # User -> Device
    assert clean_graph.graph.has_edge(f"user:{user_id}", f"device:{dev_id}")
    # Device -> Session
    assert clean_graph.graph.has_edge(f"device:{dev_id}", f"session:{sess_id}")
    # Session -> Event
    assert clean_graph.graph.has_edge(f"session:{sess_id}", f"event:{ev_id}")
    # Event -> App
    assert clean_graph.graph.has_edge(f"event:{ev_id}", f"app:{app_name}")
    # Event -> Network
    assert clean_graph.graph.has_edge(f"event:{ev_id}", f"net:{dest}")
    # Event -> Incident
    assert clean_graph.graph.has_edge(f"event:{ev_id}", f"incident:{inc_id}")

def test_incident_subgraph_extraction(clean_graph):
    """
    Verify get_incident_subgraph extracts precisely the nodes and edges associated with the incident.
    """
    now = datetime.now(timezone.utc)
    user_id = "victim_bob"
    dev_id = "DEV_DESKTOP_01"
    inc_id = "INC_SUBGRAPH_001"

    ev1 = {
        "event_id": "ev_01",
        "event_type": "SUSPICIOUS_DOWNLOAD",
        "timestamp": (now - timedelta(minutes=5)).isoformat(),
        "user_id": user_id,
        "device_id": dev_id,
        "risk_score": 75.0,
        "features": {
            "app_name": "chrome.exe",
            "file_name": "invoice_update.exe",
            "destination_ip": "192.0.2.10",
            "description": "Executable download from suspicious IP"
        }
    }
    ev2 = {
        "event_id": "ev_02",
        "event_type": "SUSPICIOUS_PROCESS_STARTED",
        "timestamp": now.isoformat(),
        "user_id": user_id,
        "device_id": dev_id,
        "risk_score": 90.0,
        "features": {
            "app_name": "invoice_update.exe",
            "destination_ip": "198.51.100.99",
            "description": "Dropped binary initiated outbound socket"
        }
    }

    clean_graph.ingest_event(ev1)
    clean_graph.ingest_event(ev2, previous_event_id="ev_01")
    clean_graph.add_incident_node(inc_id, severity="HIGH")
    clean_graph.link_event_to_incident("ev_01", inc_id)
    clean_graph.link_event_to_incident("ev_02", inc_id)

    subgraph = clean_graph.get_incident_subgraph(inc_id)
    assert subgraph["found"] is True
    assert subgraph["incident_id"] == inc_id
    assert subgraph["total_nodes"] >= 6
    assert subgraph["total_edges"] >= 6

    node_types = {n["type"] for n in subgraph["nodes"]}
    assert "Incident" in node_types
    assert "Event" in node_types
    assert "User" in node_types
    assert "Device" in node_types
    assert "Application" in node_types

def test_lateral_movement_and_blast_radius(clean_graph):
    """
    Verify lateral movement risk scoring and categorization of affected vs clean nodes.
    """
    inc_id = "INC_LATERAL_TEST"
    now = datetime.now(timezone.utc).isoformat()

    ev = {
        "event_id": "ev_c2_burst",
        "event_type": "C2_BEACONING",
        "timestamp": now,
        "user_id": "admin_sys",
        "device_id": "DEV_SERVER_CORE",
        "risk_score": 92.0,
        "features": {
            "app_name": "cmd.exe",
            "destination_ip": "198.51.100.22",
            "description": "High frequency beaconing to external C2"
        }
    }
    clean_graph.ingest_event(ev)
    clean_graph.add_incident_node(inc_id, severity="CRITICAL")
    clean_graph.link_event_to_incident("ev_c2_burst", inc_id)

    lm = clean_graph.get_lateral_movement_analysis(inc_id)
    assert lm["incident_id"] == inc_id
    assert lm["lateral_movement_risk"] == "CRITICAL"
    assert lm["blast_radius_nodes"] > 0
    assert len(lm["affected_instances"]) >= 1
    
    # Check PuppyGraph-style Cypher query generation
    cypher = lm["current_cypher_query"]
    assert "MATCH (u:User)-[:USES]->(d:Device)" in cypher
    assert "OPTIONAL MATCH (a)-[:CONNECTS_TO]->(net:NetworkEntity)" in cypher
    assert inc_id in cypher

def test_causal_sequence_explanation(clean_graph):
    """
    Verify explain_causal_sequence generates chronological narrative steps.
    """
    inc_id = "INC_NARRATIVE"
    t1 = "2026-11-01T10:00:00Z"
    t2 = "2026-11-01T10:05:00Z"

    e1 = {
        "event_id": "e_narr_1",
        "event_type": "PHISHING_URL_CLICKED",
        "timestamp": t1,
        "user_id": "user1",
        "device_id": "DEV1",
        "risk_score": 60.0,
        "features": {"description": "User clicked suspicious link in webmail"}
    }
    e2 = {
        "event_id": "e_narr_2",
        "event_type": "MALICIOUS_FILE_DROPPED",
        "timestamp": t2,
        "user_id": "user1",
        "device_id": "DEV1",
        "risk_score": 88.0,
        "features": {"description": "File payload.exe saved to AppData/Temp"}
    }

    clean_graph.ingest_event(e1)
    clean_graph.ingest_event(e2, previous_event_id="e_narr_1")
    clean_graph.add_incident_node(inc_id, severity="HIGH")
    clean_graph.link_event_to_incident("e_narr_1", inc_id)
    clean_graph.link_event_to_incident("e_narr_2", inc_id)

    narrative = clean_graph.explain_causal_sequence(inc_id)
    assert len(narrative) == 2
    assert "Step 1" in narrative[0]
    assert "User clicked suspicious link in webmail" in narrative[0]
    assert "Step 2" in narrative[1]
    assert "File payload.exe saved to AppData/Temp" in narrative[1]

def test_api_incident_graph_endpoint(api_client):
    """
    Verify the REST API endpoint GET /api/incidents/{incident_id}/graph works end-to-end.
    """
    # 1. Trigger reconstruction from current events or simulate an incident
    now = datetime.now(timezone.utc)
    ev_threat = {
        "event_id": f"ev_api_g_{uuid.uuid4().hex[:6]}",
        "event_type": "SUSPICIOUS_DOWNLOAD",
        "timestamp": now.isoformat(),
        "user_id": "test_graph_user",
        "device_id": "DEV_GRAPH_TEST",
        "risk_score": 90.0,
        "anomaly_score": 80.0,
        "behavioral_drift": 50.0,
        "features": json.dumps({
            "is_test_event": False,
            "status": "DANGEROUS",
            "file_name": "malicious_tool.exe",
            "app_name": "chrome.exe",
            "destination_ip": "198.51.100.88",
            "description": "High-risk executable download detected"
        })
    }
    db = services["db"]
    db.save_event(ev_threat)

    # Reconstruct incidents
    reconstructor = services["incident_reconstructor"]
    incidents = reconstructor.reconstruct_from_events([ev_threat])
    assert len(incidents) > 0, "Expected an incident to be formed for dangerous event"
    inc_id = incidents[0]["incident_id"]

    # 2. Call GET /api/incidents/{incident_id}/graph
    resp = api_client.get(f"/api/incidents/{inc_id}/graph")
    assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"
    data = resp.json()

    assert data["incident_id"] == inc_id
    assert "subgraph" in data
    assert data["subgraph"]["found"] is True
    assert "lateral_movement_analysis" in data
    assert "cypher_query" in data
    assert "causal_explanation" in data
    assert len(data["causal_explanation"]) >= 1
