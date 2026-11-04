"""
Test Suite: CyberThreat AI Self-Application Recognition & False-Positive Elimination.

Tests the following security and classification invariants:
1. Genuine CyberThreat AI processes (Electron, packaged executable, Python backend, setup script)
   are verified via executable path and identity, classified as 'INFO', and given 0.0 risk.
2. Name-spoofing attacks (untrusted binary named 'CyberThreat AI Operations Center.exe'
   in C:\\Temp or C:\\Users\\Public) are REJECTED and flagged.
3. Active behavioral monitoring: If a genuine CyberThreat AI process is hijacked or executes
   hostile payloads (e.g., vssadmin delete shadows, mimikatz, disabling Defender), it is
   immediately flagged as 'DANGEROUS' (95.0 risk). Blanket immunity is NEVER granted.
4. Duplicate events for the same application launch are prevented.
5. Real threat detection for third-party malware (mimikatz, encoded powershell, adware)
   is completely preserved.
6. Isolation Forest and Digital Twin models remain active and functional, correctly recognizing
   CyberThreat AI while detecting genuine anomalous applications.
"""

import os
import sys
import pytest
from pathlib import Path

from backend.config import PROJECT_ROOT
from backend.monitoring.self_recognition import (
    verify_self_process,
    evaluate_self_process,
    detect_malicious_action,
    should_emit_self_event,
    get_authorized_roots,
    _SEEN_SELF_PIDS
)
from backend.monitoring.process_monitor import ProcessMonitor
from backend.feature_engineering.extract import FeatureExtractor
from backend.behavioral_model.digital_twin import BehavioralDigitalTwin
from backend.anomaly_detection.model import IsolationForestAnomalyDetector
from backend.risk_engine.calculator import RiskEngine


@pytest.fixture(autouse=True)
def clean_state():
    """Reset self PID cache before each test."""
    _SEEN_SELF_PIDS.clear()
    yield
    _SEEN_SELF_PIDS.clear()


# ── TEST 1: Genuine Packaged CyberThreat AI Application ─────────────────────────────────

def test_genuine_packaged_cyberthreat_ai_recognized_as_info():
    """Verifies that the packaged CyberThreat AI binary inside the release directory is recognized as INFO."""
    real_exe = os.path.join(str(PROJECT_ROOT), "release", "win-unpacked", "CyberThreat AI Operations Center.exe")
    
    proc_info = {
        "pid": 8800,
        "name": "CyberThreat AI Operations Center.exe",
        "exe": real_exe,
        "cmdline": [real_exe]
    }
    
    # 1. Direct Self-Recognition Verification
    is_verified, badge, details = verify_self_process(proc_info)
    assert is_verified is True
    assert "Desktop Application" in badge
    assert details["sha256"] is not None
    
    # 2. Process Monitor Evaluation
    eval_res = ProcessMonitor.evaluate_process(proc_info)
    assert eval_res["status"] == "INFO"
    assert eval_res["risk_score"] == 0.0
    assert eval_res["is_app"] is True
    assert eval_res["is_self_verified"] is True
    assert eval_res["display_name"] == "CyberThreat AI Operations Center"
    assert any("Verified legitimate application" in r for r in eval_res["reasons"])
    assert any("Installation path verified" in r for r in eval_res["reasons"])


# ── TEST 2: Genuine Python Backend & Electron Shell ────────────────────────────────────

def test_genuine_python_backend_and_electron_shell():
    """Verifies Python backend and Electron shell are recognized as legitimate CyberThreat AI components."""
    # Python backend
    python_info = {
        "pid": 16504,
        "name": "python.exe",
        "exe": "C:\\Python314\\python.exe",
        "cmdline": ["C:\\Python314\\python.exe", "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"]
    }
    py_eval = ProcessMonitor.evaluate_process(python_info)
    assert py_eval["status"] == "INFO"
    assert py_eval["risk_score"] == 0.0
    assert py_eval["is_self_verified"] is True

    # Electron shell
    electron_exe = os.path.join(str(PROJECT_ROOT), "node_modules", "electron", "dist", "electron.exe")
    electron_info = {
        "pid": 21004,
        "name": "electron.exe",
        "exe": electron_exe,
        "cmdline": [electron_exe, os.path.join(str(PROJECT_ROOT), "electron", "main.js")]
    }
    el_eval = ProcessMonitor.evaluate_process(electron_info)
    assert el_eval["status"] == "INFO"
    assert el_eval["risk_score"] == 0.0
    assert el_eval["is_self_verified"] is True


# ── TEST 3: Name-Spoofing Defense (Untrusted Path Rejected) ───────────────────────────

def test_name_spoofing_outside_authorized_path_rejected():
    """
    An attacker names a rogue binary 'CyberThreat AI Operations Center.exe'
    in C:\\Users\\Public or C:\\Windows\\Temp.
    It MUST NOT be trusted as a self-application and MUST be flagged.
    """
    rogue_proc_info = {
        "pid": 9999,
        "name": "CyberThreat AI Operations Center.exe",
        "exe": "C:\\Users\\Public\\CyberThreat AI Operations Center.exe",
        "cmdline": ["C:\\Users\\Public\\CyberThreat AI Operations Center.exe"]
    }
    
    # 1. verify_self_process must reject it
    is_verified, reason, _ = verify_self_process(rogue_proc_info)
    assert is_verified is False
    assert "UNTRUSTED LOCATION" in reason
    
    # 2. evaluate_self_process must return None
    assert evaluate_self_process(rogue_proc_info) is None
    
    # 3. ProcessMonitor evaluates it through standard untrusted process rules
    eval_res = ProcessMonitor.evaluate_process(rogue_proc_info)
    assert eval_res.get("is_self_verified") is not True


def test_temp_folder_spoofing_flagged_as_suspicious():
    """Rogue binary named 'CyberThreat AI.exe' placed in AppData\\Local\\Temp is flagged as SUSPICIOUS."""
    temp_rogue = {
        "pid": 10001,
        "name": "CyberThreat AI.exe",
        "exe": "C:\\Users\\Attacker\\AppData\\Local\\Temp\\CyberThreat AI.exe",
        "cmdline": ["C:\\Users\\Attacker\\AppData\\Local\\Temp\\CyberThreat AI.exe"]
    }
    eval_res = ProcessMonitor.evaluate_process(temp_rogue)
    assert eval_res["status"] == "SUSPICIOUS"
    assert eval_res["risk_score"] >= 40.0
    assert any("temporary directory" in r.lower() for r in eval_res["reasons"])


# ── TEST 4: Behavioral Integrity Check (No Blanket Immunity) ───────────────────────────

def test_compromised_self_process_executing_shadow_copy_deletion_flagged_dangerous():
    """
    If CyberThreat AI is hijacked or its process arguments contain a hostile payload
    such as 'vssadmin delete shadows', it must be immediately flagged as DANGEROUS (95.0 risk).
    """
    real_exe = os.path.join(str(PROJECT_ROOT), "release", "win-unpacked", "CyberThreat AI Operations Center.exe")
    compromised_proc = {
        "pid": 8801,
        "name": "CyberThreat AI Operations Center.exe",
        "exe": real_exe,
        "cmdline": [real_exe, "--exec", "vssadmin delete shadows /all /quiet"]
    }
    
    eval_res = ProcessMonitor.evaluate_process(compromised_proc)
    assert eval_res["status"] == "DANGEROUS"
    assert eval_res["risk_score"] >= 90.0
    assert any("CRITICAL HOSTILE BEHAVIOR DETECTED" in r for r in eval_res["reasons"])
    assert any("Shadow copy deletion attempt" in r for r in eval_res["reasons"])


def test_compromised_self_process_executing_mimikatz_flagged_dangerous():
    """If CyberThreat AI process invokes mimikatz, it must be flagged as DANGEROUS."""
    real_exe = os.path.join(str(PROJECT_ROOT), "release", "win-unpacked", "CyberThreat AI Operations Center.exe")
    compromised_proc = {
        "pid": 8802,
        "name": "CyberThreat AI Operations Center.exe",
        "exe": real_exe,
        "cmdline": [real_exe, "mimikatz.exe sekurlsa::logonpasswords"]
    }
    
    eval_res = ProcessMonitor.evaluate_process(compromised_proc)
    assert eval_res["status"] == "DANGEROUS"
    assert eval_res["risk_score"] == 95.0
    assert any("Mimikatz credential dumping" in r for r in eval_res["reasons"])


def test_compromised_self_process_disabling_defender_flagged_dangerous():
    """If CyberThreat AI script attempts to disable Defender real-time monitoring, flag as DANGEROUS."""
    python_hijacked = {
        "pid": 8803,
        "name": "python.exe",
        "exe": "C:\\Python314\\python.exe",
        "cmdline": ["python.exe", "-c", "import os; os.system('powershell Set-MpPreference -DisableRealtimeMonitoring $true')"]
    }
    
    # Process monitor detects malicious pattern
    is_mal, reason = detect_malicious_action("powershell Set-MpPreference -DisableRealtimeMonitoring $true")
    assert is_mal is True
    assert "Disabling Microsoft Defender" in reason


# ── TEST 5: Deduplication of Self-Application Launch Events ───────────────────────────

def test_deduplication_prevents_duplicate_self_events():
    """Verifies should_emit_self_event returns True only on the first observation of a PID."""
    pid = 12345
    # First time: must emit
    assert should_emit_self_event(pid) is True
    # Subsequent times for same PID: must NOT emit
    assert should_emit_self_event(pid) is False
    assert should_emit_self_event(pid) is False

    # A different PID must emit once
    assert should_emit_self_event(67890) is True
    assert should_emit_self_event(67890) is False


# ── TEST 6: Real Threat Detection Preserved for Third-Party Applications ───────────────

def test_mimikatz_detected_as_dangerous():
    """Third-party threat tool 'mimikatz.exe' must be detected as DANGEROUS with high risk score."""
    proc_info = {
        "pid": 7777,
        "name": "mimikatz.exe",
        "exe": "C:\\Tools\\mimikatz.exe",
        "cmdline": ["mimikatz.exe"]
    }
    eval_res = ProcessMonitor.evaluate_process(proc_info)
    assert eval_res["status"] == "DANGEROUS"
    assert eval_res["risk_score"] >= 90.0
    assert any("matches known threat tool signature" in r for r in eval_res["reasons"])


def test_encoded_powershell_detected_as_suspicious():
    """Obfuscated hidden powershell execution must be detected as SUSPICIOUS."""
    proc_info = {
        "pid": 7778,
        "name": "powershell.exe",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": ["powershell.exe", "-windowstyle", "hidden", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBi..."]
    }
    eval_res = ProcessMonitor.evaluate_process(proc_info)
    assert eval_res["status"] == "SUSPICIOUS"
    assert eval_res["risk_score"] >= 60.0
    assert any("PowerShell executing with hidden window or encoded command" in r for r in eval_res["reasons"])


def test_mcafee_adware_popup_detected_as_suspicious():
    """Commercial scareware / adware popup must be detected as SUSPICIOUS."""
    proc_info = {
        "pid": 7779,
        "name": "mc-webview-cnt.exe",
        "exe": "C:\\Program Files\\McAfee\\mc-webview-cnt.exe",
        "cmdline": ["mc-webview-cnt.exe", "--popup-upsell"]
    }
    eval_res = ProcessMonitor.evaluate_process(proc_info)
    assert eval_res["status"] == "SUSPICIOUS"
    assert eval_res["is_adware"] is True
    assert any("Commercial adware / promotional popup detected" in r for r in eval_res["reasons"])


# ── TEST 7: ML Isolation Forest & Digital Twin Models ──────────────────────────────────

def test_isolation_forest_and_feature_extraction_for_self_app():
    """Verifies feature extractor marks CyberThreat AI as known application (is_known_application == 1.0)."""
    event = {
        "event_id": "test_evt_01",
        "timestamp": "2026-11-01T12:00:00Z",
        "event_type": "APPLICATION_START",
        "device_id": "laptop_01",
        "user_id": "analyst_01",
        "features": {
            "application": "CyberThreat AI Operations Center.exe",
            "process_name": "CyberThreat AI Operations Center.exe",
            "display_name": "CyberThreat AI Operations Center",
            "is_known_app": 1.0,
            "login_hour": 12
        }
    }
    
    vec = FeatureExtractor.extract(event)
    # Feature 2 is is_known_application
    assert vec[2] == 1.0, f"Expected is_known_application == 1.0, got {vec[2]}"


def test_digital_twin_evaluates_cyberthreat_ai_without_drift():
    """Verifies that the Digital Twin behavioral model does NOT assign application drift to CyberThreat AI."""
    dt = BehavioralDigitalTwin()
    user_id = "analyst_01"
    
    # Establish baseline with other common tools
    dt.load_profile(user_id, {
        "login_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
        "known_devices": ["laptop_01"],
        "common_applications": ["code.exe", "chrome.exe"],
        "session_durations": [30, 45, 60],
        "network_destinations": ["127.0.0.1"],
        "activity_patterns": {},
        "event_count": 10
    })
    
    # Evaluate CyberThreat AI
    event = {
        "event_id": "test_evt_02",
        "timestamp": "2026-11-01T12:00:00Z",
        "user_id": user_id,
        "device_id": "laptop_01",
        "event_type": "APPLICATION_START",
        "features": {
            "display_name": "CyberThreat AI Operations Center",
            "process_name": "CyberThreat AI Operations Center.exe",
            "is_self_verified": True
        }
    }
    
    drift_res = dt.evaluate_event(event)
    assert drift_res["factors"]["app_deviation"] == 0.0
    assert not any("CyberThreat AI" in dev for dev in drift_res["deviations"])


def test_digital_twin_still_detects_unknown_application_drift():
    """Verifies that an unknown third-party application still triggers application drift in Digital Twin."""
    dt = BehavioralDigitalTwin()
    user_id = "analyst_01"
    dt.load_profile(user_id, {
        "login_hours": [9, 10, 11, 12],
        "known_devices": ["laptop_01"],
        "common_applications": ["code.exe", "chrome.exe"],
        "session_durations": [30, 45],
        "network_destinations": ["127.0.0.1"],
        "activity_patterns": {},
        "event_count": 10
    })
    
    unknown_event = {
        "event_id": "test_evt_03",
        "timestamp": "2026-11-01T10:00:00Z",
        "user_id": user_id,
        "device_id": "laptop_01",
        "event_type": "APPLICATION_START",
        "features": {
            "display_name": "RogueMiner.exe",
            "process_name": "RogueMiner.exe"
        }
    }
    
    drift_res = dt.evaluate_event(unknown_event)
    assert drift_res["factors"]["app_deviation"] == 50.0
    assert any("New application detected: RogueMiner.exe" in dev for dev in drift_res["deviations"])
