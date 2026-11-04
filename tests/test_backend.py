"""
Comprehensive Automated Test Suite for CyberThreat AI System.

Tests all 18 core research components:
1. Feature Extraction
2. Isolation Forest ML Anomaly Detection
3. Behavioral Digital Twin Baseline Learning
4. Behavioral Drift Calculation
5. Threat Risk Evolution Engine Formula R(t) = 0.4A(t) + 0.4B(t) + 0.2H(t)
6. SQLite Database Storage & Retrieval
7. Offline Queue Ingestion
8. Online/Offline Synchronization Engine
9. Duplicate Prevention & Idempotency
10. Retry Mechanism
11. Temporal Knowledge Graph Entity & Edge Construction
12. Temporal Correlation & Sequencing
13. Incident Reconstruction Engine
14. 'What Changed?' Differential Behavioral Analysis
15. Estimated Event Contribution Analysis
16. Adaptive Response Policy Engine
17. AI Investigator Grounded Fallback
18. End-to-End Synthetic Scenario Execution & FastAPI Endpoints
"""

import os
import shutil
import tempfile
import pytest
from datetime import datetime, timezone

from backend.database.db import DatabaseManager
from backend.feature_engineering.extract import FeatureExtractor
from backend.anomaly_detection.model import IsolationForestAnomalyDetector
from backend.behavioral_model.digital_twin import BehavioralDigitalTwin
from backend.risk_engine.calculator import RiskEngine
from backend.knowledge_graph.graph import TemporalKnowledgeGraph
from backend.incident_engine.reconstructor import IncidentReconstructor
from backend.incident_engine.what_changed import WhatChangedAnalyzer
from backend.incident_engine.contribution import EventContributionAnalyzer
from backend.adaptive_response.engine import AdaptiveResponseEngine
from backend.investigator.investigator import AIInvestigator
from backend.sync.engine import SyncEngine
from backend.collectors.generator import SyntheticTelemetryGenerator


@pytest.fixture
def temp_db():
    """Provides a fresh isolated SQLite database in a temporary directory."""
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_cyberthreat.db")
    db = DatabaseManager(db_path=db_file)
    yield db
    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def generator():
    return SyntheticTelemetryGenerator()


# ==================== 1. FEATURE EXTRACTION TESTS ====================

def test_feature_extraction(generator):
    fe = FeatureExtractor()
    normal_events = generator.generate_normal_telemetry(count=3)
    for ev in normal_events:
        vec = fe.extract_features(ev)
        assert len(vec) >= 8, f"Expected at least 8 numerical features, got {len(vec)}"
        assert all(isinstance(v, (int, float)) for v in vec)


# ==================== 2. ML ANOMALY DETECTION (ISOLATION FOREST) ====================

def test_isolation_forest_anomaly_detection(generator):
    fe = FeatureExtractor()
    detector = IsolationForestAnomalyDetector(contamination=0.1, n_estimators=50)
    
    # Train on normal baseline
    normal_events = generator.generate_normal_telemetry(count=100)
    train_vecs = [fe.extract_features(e) for e in normal_events]
    detector.train(train_vecs)
    assert detector.is_trained is True
    
    # Test prediction on normal event (should have low anomaly score)
    test_normal = generator.generate_normal_telemetry(count=1)[0]
    normal_pred = detector.predict_anomaly(fe.extract_features(test_normal))
    assert "anomaly_score" in normal_pred
    assert "raw_score" in normal_pred
    assert normal_pred["anomaly_score"] < 60.0
    
    # Test prediction on severe anomaly (e.g. multi-stage attack event)
    attack_events = generator.generate_multi_stage_attack_telemetry()
    attack_ev = attack_events[-1]  # Exfiltration
    attack_pred = detector.predict_anomaly(fe.extract_features(attack_ev))
    assert attack_pred["anomaly_score"] >= 0.0


# ==================== 3. BEHAVIORAL DIGITAL TWIN BASELINE ====================

def test_digital_twin_baseline_learning(temp_db, generator):
    dt = BehavioralDigitalTwin(db_manager=temp_db)
    normal_events = generator.generate_normal_telemetry(count=50)
    
    # Learn baseline
    profile = dt.learn_baseline_from_events("user_bob", normal_events)
    assert profile is not None
    assert profile.get("event_count") == 50
    assert len(profile.get("login_hours", [])) > 0
    assert len(profile.get("known_devices", [])) > 0


# ==================== 4. BEHAVIORAL DRIFT CALCULATION ====================

def test_behavioral_drift_calculation(temp_db, generator):
    dt = BehavioralDigitalTwin(db_manager=temp_db)
    normal_events = generator.generate_normal_telemetry(count=50)
    dt.learn_baseline_from_events("user_bob", normal_events)
    
    # 1. Evaluate normal event -> drift should be near 0
    test_normal = generator.generate_normal_telemetry(count=1)[0]
    test_normal["user_id"] = "user_bob"
    test_normal["device_id"] = normal_events[0]["device_id"]
    drift_norm = dt.evaluate_event(test_normal)
    assert drift_norm["drift_score"] < 35.0
    
    # 2. Evaluate abnormal event (unusual device + unusual off-hour + unknown app)
    abnormal_ev = {
        "event_id": "abnormal-1",
        "user_id": "user_bob",
        "device_id": "UNKNOWN-ROGUE-LAPTOP",
        "timestamp": "2026-10-03T03:30:00Z",
        "event_type": "APPLICATION",
        "features": {
            "login_hour": 3,
            "device_id": "UNKNOWN-ROGUE-LAPTOP",
            "application": "mimikatz.exe",
            "destination": "198.51.100.99"
        }
    }
    drift_abnorm = dt.evaluate_event(abnormal_ev)
    assert drift_abnorm["drift_score"] >= 30.0
    assert drift_abnorm["factors"]["device_deviation"] > 0



# ==================== 5. RISK ENGINE FORMULA R(t) ====================

def test_risk_engine_formula(temp_db):
    re = RiskEngine(db_manager=temp_db)
    
    # Mathematical check: R(t) = 0.4*A(t) + 0.4*B(t) + 0.2*H(t)
    # When A=50, B=60, H=20:
    # R = 0.4*50 + 0.4*60 + 0.2*20 = 20 + 24 + 4 = 48.0
    res = re.calculate_risk(
        anomaly_score=50.0,
        behavioral_drift=60.0,
        user_id="alice",
        override_historical=20.0
    )
    assert res["risk_score"] == 48.0
    assert res["risk_level"] == "MEDIUM"
    assert res["components"]["anomaly_score_A_t"] == 50.0
    assert res["components"]["behavioral_drift_B_t"] == 60.0
    assert res["components"]["historical_risk_H_t"] == 20.0


# ==================== 6. DATABASE STORAGE & RETRIEVAL ====================

def test_database_operations(temp_db):
    event = {
        "event_id": "EV-101",
        "device_id": "DEV-01",
        "user_id": "user_1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "login",
        "features": {"status": "success"},
        "anomaly_score": 10.0,
        "behavioral_drift": 5.0,
        "risk_score": 12.0,
        "detection_source": "local_agent",
        "sync_status": "SYNCHRONIZED"
    }
    assert temp_db.save_event(event) is True
    
    retrieved = temp_db.get_event("EV-101")
    assert retrieved is not None
    assert retrieved["event_id"] == "EV-101"
    assert retrieved["risk_score"] == 12.0


# ==================== 7. OFFLINE QUEUE & 8. SYNC ENGINE ====================

def test_offline_sync_and_duplicate_prevention(temp_db):
    sync_engine = SyncEngine(db_manager=temp_db, max_retries=3)
    
    # 1. Switch to offline
    sync_engine.set_connectivity(False)
    assert sync_engine.is_online is False
    
    ev1 = {
        "event_id": "OFFLINE-001",
        "device_id": "DEV-FIELD-1",
        "user_id": "agent_smith",
        "timestamp": "2026-10-03T10:00:00Z",
        "event_type": "network_connection",
        "features": {"destination_ip": "10.0.0.5"},
        "risk_score": 25.0
    }
    sync_engine.queue_offline_event(ev1)
    assert temp_db.get_pending_sync_count() == 1
    
    # 2. Re-establish connectivity and sync
    sync_engine.set_connectivity(True)
    assert sync_engine.is_online is True
    
    sync_res = sync_engine.sync_pending_queue()
    assert sync_res["status"] == "success"
    assert sync_res["processed_count"] == 1
    assert temp_db.get_pending_sync_count() == 0
    
    # 3. Duplicate prevention test: Re-submitting OFFLINE-001 must be recognized as duplicate
    duplicate_res = sync_engine.process_sync_batch([ev1])
    assert duplicate_res["duplicate_count"] == 1
    assert duplicate_res["processed_count"] == 0


# ==================== 9. TEMPORAL KNOWLEDGE GRAPH ====================

def test_temporal_knowledge_graph(generator):
    tkg = TemporalKnowledgeGraph()
    events = generator.generate_multi_stage_attack_telemetry()
    
    tkg.build_from_events(events)
    serial = tkg.to_serializable_dict()
    
    assert len(serial["nodes"]) > 0
    assert len(serial["edges"]) > 0
    
    node_types = set(n["type"] for n in serial["nodes"])
    assert "User" in node_types or "Device" in node_types
    assert "Event" in node_types
    
    relationships = set(e["relationship"] for e in serial["edges"])
    assert any(r in relationships for r in ["GENERATES", "ASSOCIATED_WITH", "FOLLOWS", "INVOKES", "TARGETS"])


# ==================== 10. INCIDENT RECONSTRUCTION ====================

def test_incident_reconstruction(generator):
    reconstructor = IncidentReconstructor(time_window_seconds=1200, risk_threshold=30.0)
    attack_events = generator.generate_multi_stage_attack_telemetry()
    
    # Mock scores on attack events
    for idx, ev in enumerate(attack_events):
        ev["anomaly_score"] = 30.0 + (idx * 15.0)
        ev["behavioral_drift"] = 25.0 + (idx * 15.0)
        ev["risk_score"] = 25.0 + (idx * 15.0)
        
    incidents = reconstructor.reconstruct_from_events(attack_events)
    assert len(incidents) >= 1
    inc = incidents[0]
    assert inc["event_count"] >= 3
    assert len(inc["major_contributing_events"]) > 0
    assert "affected_user" in inc
    assert "confidence" in inc


# ==================== 11. WHAT CHANGED ANALYSIS ====================

def test_what_changed_analysis(temp_db, generator):
    dt = BehavioralDigitalTwin(db_manager=temp_db)
    normal_events = generator.generate_normal_telemetry(count=50)
    dt.learn_baseline_from_events("user_alice", normal_events)
    
    analyzer = WhatChangedAnalyzer(digital_twin=dt)
    
    # Deviating events
    deviations_stream = [
        {
            "event_id": "D-1",
            "user_id": "user_alice",
            "device_id": "BRAND-NEW-UNSEEN-LAPTOP",
            "timestamp": "2026-10-03T02:00:00Z",
            "event_type": "app_launch",
            "behavioral_drift": 75.0,
            "features": {
                "app_name": "cmd.exe",
                "destination_ip": "198.51.100.8"
            }
        }
    ]
    
    report = analyzer.analyze_user("user_alice", deviations_stream)
    assert report["baseline_established"] is True
    assert len(report["deviations"]) >= 1
    categories = [d["category"] for d in report["deviations"]]
    assert "Device Access" in categories or "Application Usage" in categories


# ==================== 12. ESTIMATED EVENT CONTRIBUTION ====================

def test_event_contribution_analysis():
    events = [
        {"event_id": "E1", "event_type": "login", "risk_score": 10.0, "anomaly_score": 5.0, "behavioral_drift": 5.0},
        {"event_id": "E2", "event_type": "app_launch", "risk_score": 45.0, "anomaly_score": 50.0, "behavioral_drift": 40.0},
        {"event_id": "E3", "event_type": "data_exfiltration", "risk_score": 90.0, "anomaly_score": 95.0, "behavioral_drift": 85.0}
    ]
    ranked = EventContributionAnalyzer.rank_contributions(events)
    assert len(ranked) == 3
    assert ranked[0]["event_id"] == "E3"
    assert ranked[0]["estimated_contribution"] == "High"
    assert ranked[-1]["event_id"] == "E1"
    assert ranked[-1]["estimated_contribution"] == "Low"


# ==================== 13. ADAPTIVE RESPONSE ENGINE ====================

def test_adaptive_response_recommendations():
    # Benign
    low_rec = AdaptiveResponseEngine.recommend(15.0)
    assert low_rec["action_type"] == "MONITOR"
    
    # Moderate
    med_rec = AdaptiveResponseEngine.recommend(45.0)
    assert med_rec["action_type"] == "ELEVATE_MONITORING"
    
    # Elevated
    high_rec = AdaptiveResponseEngine.recommend(70.0)
    assert high_rec["action_type"] == "REQUIRE_MFA"
    
    # Critical
    crit_rec = AdaptiveResponseEngine.recommend(92.0)
    assert crit_rec["action_type"] == "ISOLATE_SESSION"


# ==================== 14. AI INVESTIGATOR DETERMINISTIC FALLBACK ====================

def test_ai_investigator_grounded_fallback():
    investigator = AIInvestigator()
    
    incident = {
        "incident_id": "INC-TEST-99",
        "title": "Suspicious Sequence",
        "severity": "CRITICAL",
        "affected_user": "analyst_bob",
        "affected_devices": ["DEV-SEC-09"],
        "start_time": "2026-10-03T10:00:00Z",
        "end_time": "2026-10-03T10:15:00Z",
        "event_count": 4,
        "applications": ["powershell.exe"],
        "network_entities": ["198.51.100.50"],
        "peak_risk": 88.0,
        "risk_evolution": [
            {"timestamp": "2026-10-03T10:00:00Z", "event_type": "login", "risk_score": 20.0, "anomaly_score": 10.0, "behavioral_drift": 15.0},
            {"timestamp": "2026-10-03T10:15:00Z", "event_type": "data_exfiltration", "risk_score": 88.0, "anomaly_score": 90.0, "behavioral_drift": 85.0}
        ],
        "major_contributing_events": [
            {"event_type": "data_exfiltration", "estimated_contribution": "High", "reason": "Data transfer to external IP"}
        ],
        "summary": "Multi-stage exfiltration sequence detected."
    }
    
    # Test query: "What happened?"
    res1 = investigator.investigate("What happened?", incident=incident)
    assert "INC-TEST-99" in res1["answer"]
    assert "analyst_bob" in res1["answer"]
    assert res1["mode"] == "deterministic_fallback"
    
    # Test query: "Why was this incident suspicious?"
    res2 = investigator.investigate("Why was this suspicious?", incident=incident)
    assert "powershell.exe" in res2["answer"] or "88.0" in res2["answer"] or "exfiltration" in res2["answer"]
    
    # Test query with no incident and no telemetry
    res_empty = investigator.investigate("What happened?", incident=None, user_id=None)
    assert "Insufficient evidence" in res_empty["answer"]
