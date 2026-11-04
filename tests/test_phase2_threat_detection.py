"""
Phase 2 Verification Test Suite: Threat Detection Accuracy & Evidence.

Validates the Phase 2 Success Criteria:
1. Isolation Forest for ML anomaly detection.
2. Behavioral Digital Twin baseline learning and explainable drift detection.
3. Accurate detection across Websites, Downloads, Processes, and Network Connections.
4. Human-readable explainable evidence for every detection verdict.
5. Never label an unknown/unrated event as safe without sufficient evidence.
6. Controlled Safe vs Suspicious test matrix recording false-positive and false-negative rates.
"""

import pytest
from datetime import datetime, timezone

from backend.anomaly_detection.model import IsolationForestAnomalyDetector
from backend.behavioral_model.digital_twin import BehavioralDigitalTwin
from backend.feature_engineering.extract import FeatureExtractor
from backend.monitoring.domain_evaluator import DomainEvaluator
from backend.monitoring.file_monitor import FileMonitor
from backend.monitoring.process_monitor import ProcessMonitor
from backend.monitoring.network_monitor import NetworkMonitor
from backend.risk_engine.calculator import RiskEngine


def test_isolation_forest_anomaly_scoring():
    """Criterion 1: Isolation Forest detects anomalies from feature vectors."""
    detector = IsolationForestAnomalyDetector(contamination=0.1, n_estimators=50)

    # Train on normal baseline vectors (business hours 9-17, known devices, known apps)
    normal_training_events = []
    for h in range(9, 18):
        normal_training_events.append({
            "event_id": f"train_{h}",
            "device_id": "DEV_HW_LAPTOP01",
            "timestamp": f"2026-11-01T{h:02d}:00:00+00:00",
            "event_type": "APPLICATION_START",
            "features": {
                "process_name": "chrome.exe",
                "login_hour": h,
                "session_duration_min": 60,
                "destination": "google.com"
            }
        })

    vectors = [FeatureExtractor.extract(ev) for ev in normal_training_events]
    detector.train(vectors)
    assert detector.is_trained is True

    # 1. Test normal safe event
    normal_test = {
        "event_id": "test_norm_1",
        "device_id": "DEV_HW_LAPTOP01",
        "timestamp": "2026-11-01T14:30:00+00:00",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "chrome.exe",
            "login_hour": 14,
            "session_duration_min": 45,
            "destination": "google.com"
        }
    }
    pred_normal = detector.predict_anomaly(FeatureExtractor.extract(normal_test))
    assert pred_normal["anomaly_score"] < 50.0

    # 2. Test extreme outlier / anomalous event (3 AM off-hours, unknown device, unknown app)
    anomalous_test = {
        "event_id": "test_anom_1",
        "device_id": "UNKNOWN_ROGUE_DEVICE",
        "timestamp": "2026-11-01T03:15:00+00:00",
        "event_type": "NETWORK_CONNECTION",
        "features": {
            "process_name": "mimikatz.exe",
            "login_hour": 3,
            "session_duration_min": 900,
            "destination": "185.220.101.5"
        }
    }
    pred_anom = detector.predict_anomaly(FeatureExtractor.extract(anomalous_test))
    assert pred_anom["anomaly_score"] >= pred_normal["anomaly_score"]


def test_digital_twin_behavioral_baseline_and_drift():
    """Criterion 2: Behavioral Digital Twin baseline and explainable drift detection."""
    twin = BehavioralDigitalTwin()
    user_id = "analyst_alice"

    # Establish baseline of normal working behavior
    training_events = []
    for i in range(3):
        training_events.extend([
            {
                "event_id": f"base_{i}",
                "device_id": "DEV_ALICE_LAPTOP",
                "timestamp": "2026-11-01T10:00:00+00:00",
                "event_type": "APPLICATION_START",
                "features": {
                    "process_name": "code.exe",
                    "login_hour": 10,
                    "session_duration_min": 120,
                    "destination": "github.com"
                }
            },
            {
                "event_id": f"base_2_{i}",
                "device_id": "DEV_ALICE_LAPTOP",
                "timestamp": "2026-11-01T14:00:00+00:00",
                "event_type": "APPLICATION_START",
                "features": {
                    "process_name": "chrome.exe",
                    "login_hour": 14,
                    "session_duration_min": 60,
                    "destination": "google.com"
                }
            }
        ])
    twin.learn_baseline_from_events(user_id, training_events)
    profile = twin.get_profile(user_id)
    assert profile["event_count"] >= 6
    assert "DEV_ALICE_LAPTOP" in profile["known_devices"]

    # 1. Normal event matching baseline -> zero drift
    normal_ev = {
        "user_id": user_id,
        "device_id": "DEV_ALICE_LAPTOP",
        "timestamp": "2026-11-01T10:15:00+00:00",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "code.exe",
            "login_hour": 10,
            "session_duration_min": 110,
            "destination": "github.com"
        }
    }
    res_normal = twin.evaluate_event(normal_ev)
    assert res_normal["drift_score"] < 15.0
    assert len(res_normal["deviations"]) == 0

    # 2. Deviating event (unknown device, unusual hour 2 AM, new suspicious app)
    drift_ev = {
        "user_id": user_id,
        "device_id": "DEV_FOREIGN_HOST_999",
        "timestamp": "2026-11-01T02:00:00+00:00",
        "event_type": "APPLICATION_START",
        "features": {
            "process_name": "powershell_remote.exe",
            "login_hour": 2,
            "session_duration_min": 500,
            "destination": "external-c2-drop.xyz"
        }
    }
    res_drift = twin.evaluate_event(drift_ev)
    assert res_drift["drift_score"] > 40.0
    assert len(res_drift["deviations"]) >= 2
    dev_texts = " ".join(res_drift["deviations"]).lower()
    assert "new device detected" in dev_texts or "login time" in dev_texts


def test_detect_suspicious_websites_with_evidence():
    """Criterion 3a: Detect suspicious websites with explainable evidence."""
    # 1. Phishing / Suspicious TLD
    res_phish = DomainEvaluator.evaluate_url("http://secure-login-verify-account.top")
    assert res_phish["status"] in ("SUSPICIOUS", "DANGEROUS")
    assert res_phish["risk_score"] >= 35.0
    assert len(res_phish["reasons"]) > 0

    # 2. Algorithmic Domain Randomness (DGA)
    res_dga = DomainEvaluator.evaluate_url("http://xkjqpwzmnhytvr.com")
    assert res_dga["status"] in ("SUSPICIOUS", "DANGEROUS")
    assert any("entropy" in r.lower() or "dga" in r.lower() for r in res_dga["reasons"])

    # 3. Known Clean Domain
    res_safe = DomainEvaluator.evaluate_url("https://www.google.com")
    assert res_safe["status"] == "SAFE"
    assert res_safe["risk_score"] == 0.0

    # 4. Unverified Website (Insufficient Evidence) -> MUST BE UNKNOWN, NEVER FALSELY SAFE
    res_unknown = DomainEvaluator.evaluate_url("http://brand-new-site-2026.click")
    # .click is a suspicious TLD; test an unrated domain with standard/obscure TLD and 0 threat matches
    res_unrated = DomainEvaluator.evaluate_url("http://some-obscure-blog.customtld")
    assert res_unrated["status"] == "UNKNOWN"
    assert res_unrated["risk_score"] is None
    assert any("unverified" in r.lower() or "caution" in r.lower() for r in res_unrated["reasons"])


def test_detect_suspicious_downloads_with_evidence(tmp_path):
    """Criterion 3b: Detect suspicious downloads (double extensions, EICAR)."""
    # 1. Double extension detection
    res_double = FileMonitor.evaluate_file(tmp_path / "invoice_q4.pdf.exe")
    # File doesn't exist on disk yet, evaluate path heuristic
    eval_double = FileMonitor.evaluate_file("C:\\Downloads\\payroll_confidential.pdf.exe")
    assert eval_double["is_dangerous"] is True or eval_double["risk_score"] >= 70.0 or any("double extension" in r.lower() for r in eval_double["reasons"])

    # 2. EICAR Antivirus Test Signature
    eicar_file = tmp_path / "eicar_test.com"
    eicar_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    res_eicar = FileMonitor.evaluate_file(eicar_file)
    assert res_eicar["is_eicar_test"] is True
    assert res_eicar["status"] == "DANGEROUS"
    assert any("eicar" in r.lower() for r in res_eicar["reasons"])


def test_detect_suspicious_processes_with_evidence():
    """Criterion 3c: Detect suspicious processes (temp folder, encoded cmd, adware)."""
    # 1. Suspicious process name
    proc_mimi = {
        "pid": 4412,
        "name": "mimikatz.exe",
        "exe": "C:\\Tools\\mimikatz.exe",
        "cmdline": "mimikatz.exe privilege::debug"
    }
    eval_mimi = ProcessMonitor.evaluate_process(proc_mimi)
    assert eval_mimi["status"] == "DANGEROUS"
    assert eval_mimi["risk_score"] >= 70.0
    assert any("suspicious process name" in r.lower() for r in eval_mimi["reasons"])

    # 2. Suspicious Temp directory execution
    proc_temp = {
        "pid": 5512,
        "name": "payload.exe",
        "exe": "C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe",
        "cmdline": "C:\\Users\\User\\AppData\\Local\\Temp\\payload.exe -silent"
    }
    eval_temp = ProcessMonitor.evaluate_process(proc_temp)
    assert eval_temp["status"] in ("SUSPICIOUS", "DANGEROUS")
    assert any("temp" in r.lower() for r in eval_temp["reasons"])

    # 3. Safe legitimate application
    proc_safe = {
        "pid": 1200,
        "name": "notepad.exe",
        "exe": "C:\\Windows\\System32\\notepad.exe",
        "cmdline": "notepad.exe notes.txt"
    }
    eval_safe = ProcessMonitor.evaluate_process(proc_safe)
    assert eval_safe["status"] in ("SAFE", "INFO")
    assert eval_safe["risk_score"] == 0.0


def test_detect_suspicious_network_connections_with_evidence():
    """Criterion 3d: Detect non-standard egress ports and suspicious sockets."""
    # 1. High-risk C2 port (4444)
    conn_bad = {
        "remote_ip": "198.51.100.45",
        "remote_port": 4444,
        "process_name": "cmd.exe",
        "status": "ESTABLISHED"
    }
    eval_bad = NetworkMonitor.evaluate_connection(conn_bad)
    assert eval_bad["threat_status"] in ("DANGEROUS", "SUSPICIOUS")
    assert eval_bad["risk_score"] >= 60.0
    assert any("4444" in r or "command interpreter" in r.lower() for r in eval_bad["reasons"])

    # 2. Safe local / standard outbound HTTPS connection
    conn_safe = {
        "remote_ip": "142.250.190.46",  # Google IP
        "remote_port": 443,
        "process_name": "chrome.exe",
        "status": "ESTABLISHED"
    }
    eval_safe = NetworkMonitor.evaluate_connection(conn_safe)
    assert eval_safe["threat_status"] in ("SAFE", "INFO")
    assert eval_safe["risk_score"] <= 15.0


def test_controlled_safe_vs_suspicious_test_matrix():
    """
    Phase 2 Primary Success Criteria:
    Test safe and suspicious scenarios separately and record actual detection results.
    Assert 0% False Positives and 0% False Negatives on controlled scenarios.
    """
    safe_scenarios = [
        {"type": "domain", "url": "https://www.google.com"},
        {"type": "domain", "url": "https://github.com"},
        {"type": "process", "info": {"pid": 101, "name": "code.exe", "exe": "C:\\Program Files\\Microsoft VS Code\\code.exe", "cmdline": ""}},
        {"type": "process", "info": {"pid": 102, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe", "cmdline": ""}},
        {"type": "network", "info": {"remote_ip": "192.168.1.50", "remote_port": 443, "process_name": "chrome.exe", "status": "ESTABLISHED"}}
    ]

    suspicious_scenarios = [
        {"type": "domain", "url": "http://paypal-auth-credential-reset.top"},
        {"type": "domain", "url": "http://185.220.101.45/login"},
        {"type": "file", "path": "C:\\Downloads\\salary_bonus.pdf.exe"},
        {"type": "process", "info": {"pid": 201, "name": "mimikatz.exe", "exe": "C:\\temp\\mimikatz.exe", "cmdline": "privilege::debug"}},
        {"type": "network", "info": {"remote_ip": "203.0.113.10", "remote_port": 4444, "process_name": "powershell.exe", "status": "ESTABLISHED"}}
    ]

    false_positives = 0
    false_negatives = 0

    # 1. Evaluate Safe Scenarios
    for s in safe_scenarios:
        if s["type"] == "domain":
            res = DomainEvaluator.evaluate_url(s["url"])
            if res["status"] in ("DANGEROUS", "SUSPICIOUS"):
                false_positives += 1
        elif s["type"] == "process":
            res = ProcessMonitor.evaluate_process(s["info"])
            if res["status"] in ("DANGEROUS", "SUSPICIOUS"):
                false_positives += 1
        elif s["type"] == "network":
            res = NetworkMonitor.evaluate_connection(s["info"])
            if res["threat_status"] in ("DANGEROUS", "SUSPICIOUS"):
                false_positives += 1

    # 2. Evaluate Suspicious Scenarios
    for s in suspicious_scenarios:
        if s["type"] == "domain":
            res = DomainEvaluator.evaluate_url(s["url"])
            if res["status"] not in ("DANGEROUS", "SUSPICIOUS"):
                false_negatives += 1
        elif s["type"] == "file":
            res = FileMonitor.evaluate_file(s["path"])
            if res["status"] not in ("DANGEROUS", "SUSPICIOUS"):
                false_negatives += 1
        elif s["type"] == "process":
            res = ProcessMonitor.evaluate_process(s["info"])
            if res["status"] not in ("DANGEROUS", "SUSPICIOUS"):
                false_negatives += 1
        elif s["type"] == "network":
            res = NetworkMonitor.evaluate_connection(s["info"])
            if res["threat_status"] not in ("DANGEROUS", "SUSPICIOUS"):
                false_negatives += 1

    # Record actual detection metrics
    fp_rate = false_positives / len(safe_scenarios)
    fn_rate = false_negatives / len(suspicious_scenarios)

    print(f"\n[Controlled Test Matrix Results]")
    print(f"Safe Scenarios Tested: {len(safe_scenarios)}, False Positives: {false_positives} ({fp_rate * 100:.1f}%)")
    print(f"Suspicious Scenarios Tested: {len(suspicious_scenarios)}, False Negatives: {false_negatives} ({fn_rate * 100:.1f}%)")

    assert false_positives == 0, f"Expected 0 False Positives, got {false_positives}"
    assert false_negatives == 0, f"Expected 0 False Negatives, got {false_negatives}"
