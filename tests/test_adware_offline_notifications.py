import pytest
from backend.monitoring.process_monitor import ProcessMonitor
from backend.monitoring.engine import RealSystemMonitor

def test_adware_and_scareware_evaluation():
    """Verifies that McAfee Security Scan adware popups and commercial scareware are correctly detected."""
    pm = ProcessMonitor()
    
    # 1. Test McAfee webview popup container (the exact process that rendered the user's ad)
    sample_ad_proc = {
        "pid": 21996,
        "name": "mc-webview-cnt.exe",
        "exe": "C:\\Program Files (x86)\\McAfee Security Scan\\4.2.844\\mc-webview-cnt.exe",
        "cmdline": ["mc-webview-cnt.exe"]
    }
    eval_ad = pm.evaluate_process(sample_ad_proc)
    assert eval_ad["is_adware"] is True
    assert eval_ad["status"] == "SUSPICIOUS"
    assert eval_ad["risk_score"] == 45.0
    assert "McAfee Promotional Ad Popup" in eval_ad["display_name"]
    assert any("commercial" in r.lower() or "adware" in r.lower() for r in eval_ad["reasons"])

    # 2. Test McAfee scheduler
    sample_sched = {
        "pid": 9292,
        "name": "SSScheduler.exe",
        "exe": "C:\\Program Files (x86)\\McAfee Security Scan\\4.2.844\\SSScheduler.exe",
        "cmdline": ["SSScheduler.exe"]
    }
    eval_sched = pm.evaluate_process(sample_sched)
    assert eval_sched["is_adware"] is True
    assert eval_sched["status"] == "SUSPICIOUS"

    # 3. Test clean safe offline application
    sample_safe = {
        "pid": 1234,
        "name": "notepad.exe",
        "exe": "C:\\Windows\\System32\\notepad.exe",
        "cmdline": ["notepad.exe"]
    }
    eval_safe = pm.evaluate_process(sample_safe)
    assert eval_safe["is_adware"] is False
    assert eval_safe["is_app"] is True
    assert eval_safe["risk_score"] == 0.0
    assert eval_safe["display_name"] == "Notepad"

def test_find_active_adware_processes():
    """Verifies that find_active_adware_processes correctly scans host processes."""
    pm = ProcessMonitor()
    ads = pm.find_active_adware_processes()
    assert isinstance(ads, list)
    for a in ads:
        assert a.get("is_adware") is True
        assert a.get("status") == "SUSPICIOUS"
        assert a.get("risk_score") >= 35.0
