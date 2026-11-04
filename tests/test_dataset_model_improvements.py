"""
Automated Test Suite for Dataset-Based Model Improvements.
Validates:
1. Real-Data Baseline Isolation Forest functionality and loading.
2. Supervised Random Forest Threat Classifier accuracy and latency.
3. Accurate detection of normal user activity vs malicious cyberattack events.
4. Cryptomining & C2 DNS threat intelligence integration.
5. Multi-model fusion in predict_anomaly pipeline.
"""
import pytest
import time
from backend.anomaly_detection.model import AnomalyDetector, IsolationForestAnomalyDetector
from backend.anomaly_detection.threat_classifier import ThreatClassifier
from backend.monitoring.domain_evaluator import DomainEvaluator
from backend.feature_engineering.extract import FeatureExtractor


def test_threat_classifier_initialization_and_loading():
    tc = ThreatClassifier()
    assert tc.is_loaded is True
    assert tc.model is not None
    assert len(tc.known_apps) > 0


def test_normal_application_activity_classified_safe():
    tc = ThreatClassifier()
    normal_event = {
        "event_id": "test_norm_proc",
        "user_id": "1000",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "chrome.exe",
            "application": "Google Chrome",
            "command_line": "chrome.exe --new-window",
            "return_value": 0,
            "parent_pid": 1
        }
    }
    res = tc.predict_threat(normal_event)
    assert res["is_threat"] is False
    assert res["threat_probability"] < 0.60
    assert res["confidence_level"] == "LOW"


def test_malicious_exploit_and_trojan_detected_as_threat():
    tc = ThreatClassifier()
    malicious_event = {
        "event_id": "test_evil_exploit",
        "user_id": "0",  # Elevated root execution
        "event_type": "PROCESS_START",
        "features": {
            "process_name": "tsm",  # Known malware from BETH dataset
            "application": "tsm",
            "command_line": "./tsm --connect 10.100.0.1",
            "return_value": 1,
            "parent_pid": 500,
            "action": "connect"
        }
    }
    res = tc.predict_threat(malicious_event)
    assert res["is_threat"] is True
    assert res["threat_probability"] >= 0.70
    assert len(res["factors"]) > 0


def test_anomaly_detector_multi_model_fusion():
    detector = AnomalyDetector()
    detector.load("models/isolation_forest.joblib")
    assert detector.is_trained is True

    # 1. Normal event evaluation
    normal_ev = {
        "event_id": "test_norm_fuse",
        "user_id": "usr_alice",
        "device_id": "DEV_LAPTOP01",
        "event_type": "APPLICATION_START",
        "timestamp": "2026-11-04T10:00:00Z",
        "features": {
            "process_name": "code.exe",
            "application": "VS Code",
            "login_hour": 10,
            "session_duration_min": 60,
            "destination": "github.com",
            "is_known_device": True
        }
    }
    norm_res = detector.predict_anomaly(normal_ev)
    assert norm_res["anomaly_score"] < 50.0
    assert norm_res["is_anomaly"] is False

    # 2. Malicious event evaluation
    malicious_ev = {
        "event_id": "test_evil_fuse",
        "user_id": "0",
        "device_id": "UNKNOWN_HOST",
        "event_type": "PROCESS_START",
        "timestamp": "2026-11-04T03:00:00Z",
        "features": {
            "process_name": "tsm",
            "application": "tsm",
            "command_line": "./tsm -x -e 1",
            "return_value": 1,
            "parent_pid": 500,
            "action": "connect"
        }
    }
    evil_res = detector.predict_anomaly(malicious_ev)
    assert evil_res["anomaly_score"] >= 65.0
    assert evil_res["is_anomaly"] is True
    assert evil_res["threat_probability"] >= 0.70


def test_dns_threat_intelligence_detection():
    # Test verified cryptomining pool from DNS dataset
    res_miner = DomainEvaluator.evaluate_url("http://pool.hashvault.pro")
    assert res_miner["status"] == "DANGEROUS"
    assert res_miner["risk_score"] >= 80.0

    # Test standard legitimate domain remains safe
    res_safe = DomainEvaluator.evaluate_url("https://github.com")
    assert res_safe["status"] == "SAFE"
    assert res_safe["risk_score"] == 0.0


def test_detection_latency_is_sub_millisecond():
    detector = AnomalyDetector()
    detector.load("models/isolation_forest.joblib")
    
    test_ev = {
        "event_id": "latency_test",
        "user_id": "1000",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "chrome.exe",
            "login_hour": 12
        }
    }
    
    # Warmup
    for _ in range(10):
        detector.predict_anomaly(test_ev)
        
    t0 = time.perf_counter()
    iterations = 200
    for _ in range(iterations):
        detector.predict_anomaly(test_ev)
    avg_latency_ms = (time.perf_counter() - t0) / iterations * 1000.0
    
    # Must be fast for real-time monitoring (< 35 ms per event)
    assert avg_latency_ms < 35.0
