"""
Incident Reconstruction Evaluation & Ground-Truth Benchmark.

Evaluates the Incident Reconstructor against 3 structured ground-truth attack scenarios:
1. Multi-Stage Phishing to C2 Beaconing
2. Off-Hours Credential Abuse & Lateral Movement
3. Ransomware File Staging & Bulk Data Exfiltration

Metrics Evaluated:
- Sequence Order Fidelity (Kendall's tau rank correlation and pairwise order inversion rate)
- Entity Identification Recall & Precision (User, Device, Processes, Network Endpoints)
- Patient Zero / Root Cause Identification Accuracy
- Alert Fatigue Reduction Rate (%)
"""

import json
import time
from typing import Dict, Any, List, Set, Tuple
from datetime import datetime, timezone, timedelta
from scipy.stats import kendalltau

from backend.incident_engine.reconstructor import IncidentReconstructor
from backend.feature_engineering.extract import FeatureExtractor
from backend.anomaly_detection.model import IsolationForestAnomalyDetector
from backend.behavioral_model.digital_twin import BehavioralDigitalTwin
from backend.risk_engine.calculator import RiskEngine
from backend.database.db import DatabaseManager


# ==================== GROUND TRUTH SCENARIO DEFINITIONS ====================

def create_phishing_to_c2_scenario(base_time: datetime) -> Dict[str, Any]:
    """
    Scenario 1: Ground Truth - Phishing to C2 Beaconing
    Ground Truth Sequence:
      Step 1 (T+00m): Browser opens phishing credential-harvesting domain
      Step 2 (T+03m): Malicious dropped payload saved to Downloads
      Step 3 (T+05m): Suspicious process spawned from Temp directory
      Step 4 (T+08m): Outbound socket established to known C2 server
    """
    user_id = "user_sarah"
    device_id = "DEV_FINANCE_01"
    
    events = [
        {
            "event_id": "evt_phish_01",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
            "event_type": "WEBSITE_OPENED",
            "ground_truth_order": 1,
            "ground_truth_role": "ENTRY_VECTOR",
            "features": {
                "domain": "paypal-security-update.top",
                "url": "https://paypal-security-update.top/login-verify",
                "status": "SUSPICIOUS",
                "category": "Credential Phishing",
                "is_phishing": True
            },
            "risk_score": 62.0,
            "anomaly_score": 68.0,
            "behavioral_drift": 45.0
        },
        {
            "event_id": "evt_drop_02",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=3)).isoformat(),
            "event_type": "FILE_WRITE",
            "ground_truth_order": 2,
            "ground_truth_role": "PAYLOAD_DROP",
            "features": {
                "file_name": "security_patch_installer.exe",
                "file_path": "C:\\Users\\sarah\\Downloads\\security_patch_installer.exe",
                "status": "DANGEROUS",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "is_executable": True
            },
            "risk_score": 75.0,
            "anomaly_score": 82.0,
            "behavioral_drift": 58.0
        },
        {
            "event_id": "evt_exec_03",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=5)).isoformat(),
            "event_type": "PROCESS_START",
            "ground_truth_order": 3,
            "ground_truth_role": "EXECUTION",
            "features": {
                "process_name": "security_patch_installer.exe",
                "process_path": "C:\\Users\\sarah\\AppData\\Local\\Temp\\security_patch_installer.exe",
                "command_line": "security_patch_installer.exe --silent --inject",
                "status": "DANGEROUS",
                "parent_process": "cmd.exe"
            },
            "risk_score": 84.0,
            "anomaly_score": 88.0,
            "behavioral_drift": 72.0
        },
        {
            "event_id": "evt_c2_04",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=8)).isoformat(),
            "event_type": "SOCKET_CONNECT",
            "ground_truth_order": 4,
            "ground_truth_role": "COMMAND_AND_CONTROL",
            "features": {
                "process_name": "security_patch_installer.exe",
                "destination_ip": "185.220.101.45",
                "destination_port": 4444,
                "status": "DANGEROUS",
                "is_egress": True
            },
            "risk_score": 92.0,
            "anomaly_score": 95.0,
            "behavioral_drift": 88.0
        }
    ]
    
    return {
        "scenario_name": "Scenario 1: Multi-Stage Phishing to C2 Beaconing",
        "description": "Drive-by credential phishing leading to executable payload drop, execution from temp directory, and C2 egress beacon.",
        "events": events,
        "ground_truth": {
            "order": ["evt_phish_01", "evt_drop_02", "evt_exec_03", "evt_c2_04"],
            "patient_zero_event_id": "evt_phish_01",
            "patient_zero_target": "paypal-security-update.top",
            "user": "user_sarah",
            "device": "DEV_FINANCE_01",
            "entities": {
                "users": {"user_sarah"},
                "devices": {"DEV_FINANCE_01"},
                "applications": {"security_patch_installer.exe"},
                "network_entities": {"paypal-security-update.top", "185.220.101.45"}
            }
        }
    }


def create_credential_abuse_scenario(base_time: datetime) -> Dict[str, Any]:
    """
    Scenario 2: Ground Truth - Credential Abuse & Privilege Escalation
    Ground Truth Sequence:
      Step 1 (T+00m): Anomalous off-hours authentication (02:45 AM)
      Step 2 (T+04m): PowerShell spawned with base64 encoded payload
      Step 3 (T+07m): Memory scraping targeting LSASS credential vault
      Step 4 (T+11m): Unauthorized lateral query to internal production database
    """
    user_id = "admin_dave"
    device_id = "DEV_OPS_02"
    
    events = [
        {
            "event_id": "evt_cred_01",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
            "event_type": "LOGIN",
            "ground_truth_order": 1,
            "ground_truth_role": "ANOMALOUS_AUTH",
            "features": {
                "auth_method": "password_spray",
                "hour_of_day": 2,
                "location": "unknown_vpn_endpoint",
                "status": "SUSPICIOUS"
            },
            "risk_score": 58.0,
            "anomaly_score": 64.0,
            "behavioral_drift": 50.0
        },
        {
            "event_id": "evt_ps_02",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=4)).isoformat(),
            "event_type": "PROCESS_START",
            "ground_truth_order": 2,
            "ground_truth_role": "SCRIPTING_EXECUTION",
            "features": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
                "status": "DANGEROUS"
            },
            "risk_score": 78.0,
            "anomaly_score": 85.0,
            "behavioral_drift": 65.0
        },
        {
            "event_id": "evt_lsass_03",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=7)).isoformat(),
            "event_type": "PRIVILEGE_ESCALATION",
            "ground_truth_order": 3,
            "ground_truth_role": "CREDENTIAL_DUMPING",
            "features": {
                "process_name": "powershell.exe",
                "target_process": "lsass.exe",
                "action": "OpenProcess(PROCESS_VM_READ)",
                "status": "DANGEROUS"
            },
            "risk_score": 88.0,
            "anomaly_score": 92.0,
            "behavioral_drift": 80.0
        },
        {
            "event_id": "evt_lateral_04",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=11)).isoformat(),
            "event_type": "NETWORK_CONNECTION",
            "ground_truth_order": 4,
            "ground_truth_role": "LATERAL_MOVEMENT",
            "features": {
                "process_name": "powershell.exe",
                "destination_ip": "10.0.4.15",
                "domain": "internal-prod-db.corp",
                "port": 5432,
                "status": "DANGEROUS"
            },
            "risk_score": 82.0,
            "anomaly_score": 86.0,
            "behavioral_drift": 75.0
        }
    ]
    
    return {
        "scenario_name": "Scenario 2: Off-Hours Credential Abuse & Privilege Escalation",
        "description": "Compromised credentials used during late-night hours, launching encoded PowerShell to dump LSASS credentials and pivot laterally to core DB.",
        "events": events,
        "ground_truth": {
            "order": ["evt_cred_01", "evt_ps_02", "evt_lsass_03", "evt_lateral_04"],
            "patient_zero_event_id": "evt_cred_01",
            "patient_zero_target": "password_spray",
            "user": "admin_dave",
            "device": "DEV_OPS_02",
            "entities": {
                "users": {"admin_dave"},
                "devices": {"DEV_OPS_02"},
                "applications": {"powershell.exe"},
                "network_entities": {"10.0.4.15", "internal-prod-db.corp"}
            }
        }
    }


def create_ransomware_scenario(base_time: datetime) -> Dict[str, Any]:
    """
    Scenario 3: Ground Truth - Ransomware Staging & Bulk Data Exfiltration
    Ground Truth Sequence:
      Step 1 (T+00m): Archive downloaded and extracted (financial_audit_2026.zip)
      Step 2 (T+02m): Visual Basic script payload executed (encrypt_payload.vbs)
      Step 3 (T+06m): High-frequency mass file modification & encryption burst
      Step 4 (T+09m): Ransom note drop (README_RESTORE_FILES.txt)
      Step 5 (T+12m): Bulk encrypted archive exfiltrated via outbound HTTPS tunnel
    """
    user_id = "user_kevin"
    device_id = "DEV_ACCOUNTING_03"
    
    events = [
        {
            "event_id": "evt_zip_01",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=0)).isoformat(),
            "event_type": "FILE_CREATE",
            "ground_truth_order": 1,
            "ground_truth_role": "ENTRY_ARCHIVE",
            "features": {
                "file_name": "financial_audit_2026.zip",
                "file_path": "C:\\Users\\kevin\\Downloads\\financial_audit_2026.zip",
                "status": "SUSPICIOUS"
            },
            "risk_score": 52.0,
            "anomaly_score": 58.0,
            "behavioral_drift": 35.0
        },
        {
            "event_id": "evt_vbs_02",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=2)).isoformat(),
            "event_type": "PROCESS_START",
            "ground_truth_order": 2,
            "ground_truth_role": "SCRIPT_LAUNCH",
            "features": {
                "process_name": "wscript.exe",
                "command_line": "wscript.exe C:\\Users\\kevin\\Downloads\\encrypt_payload.vbs",
                "status": "DANGEROUS"
            },
            "risk_score": 76.0,
            "anomaly_score": 80.0,
            "behavioral_drift": 62.0
        },
        {
            "event_id": "evt_enc_03",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=6)).isoformat(),
            "event_type": "FILE_WRITE",
            "ground_truth_order": 3,
            "ground_truth_role": "RAPID_ENCRYPTION",
            "features": {
                "file_name": "q3_financial_ledger.xlsx.locked",
                "action": "MASS_RENAME_ENCRYPT",
                "entropy_score": 7.98,
                "status": "DANGEROUS"
            },
            "risk_score": 94.0,
            "anomaly_score": 98.0,
            "behavioral_drift": 92.0
        },
        {
            "event_id": "evt_note_04",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=9)).isoformat(),
            "event_type": "FILE_CREATE",
            "ground_truth_order": 4,
            "ground_truth_role": "RANSOM_NOTE",
            "features": {
                "file_name": "README_RESTORE_FILES.txt",
                "description": "Ransom demand file created on Desktop",
                "status": "DANGEROUS"
            },
            "risk_score": 85.0,
            "anomaly_score": 86.0,
            "behavioral_drift": 80.0
        },
        {
            "event_id": "evt_exfil_05",
            "user_id": user_id,
            "device_id": device_id,
            "timestamp": (base_time + timedelta(minutes=12)).isoformat(),
            "event_type": "SOCKET_CONNECT",
            "ground_truth_order": 5,
            "ground_truth_role": "DATA_EXFILTRATION",
            "features": {
                "destination_ip": "194.26.29.112",
                "port": 443,
                "bytes_out": 48200000,
                "status": "DANGEROUS"
            },
            "risk_score": 96.0,
            "anomaly_score": 99.0,
            "behavioral_drift": 95.0
        }
    ]
    
    return {
        "scenario_name": "Scenario 3: Multi-Stage Ransomware Staging & Bulk Data Exfiltration",
        "description": "Encrypted archive dropped, executed via wscript, triggering mass file encryption, dropping ransom demand, and exfiltrating data out of band.",
        "events": events,
        "ground_truth": {
            "order": ["evt_zip_01", "evt_vbs_02", "evt_enc_03", "evt_note_04", "evt_exfil_05"],
            "patient_zero_event_id": "evt_zip_01",
            "patient_zero_target": "financial_audit_2026.zip",
            "user": "user_kevin",
            "device": "DEV_ACCOUNTING_03",
            "entities": {
                "users": {"user_kevin"},
                "devices": {"DEV_ACCOUNTING_03"},
                "applications": {"wscript.exe"},
                "network_entities": {"194.26.29.112"}
            }
        }
    }


# ==================== EVALUATION METRICS ENGINE ====================

def evaluate_scenario_reconstruction(scenario_data: Dict[str, Any], reconstructor: IncidentReconstructor) -> Dict[str, Any]:
    """
    Executes incident reconstruction on a scenario and computes empirical validation metrics
    against known ground truth.
    """
    name = scenario_data["scenario_name"]
    events = scenario_data["events"]
    gt = scenario_data["ground_truth"]
    
    t0 = time.perf_counter()
    incidents = reconstructor.reconstruct_from_events(events)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    
    if not incidents:
        return {
            "scenario": name,
            "reconstructed": False,
            "error": "Reconstructor produced 0 incidents for high-threat scenario"
        }
        
    inc = incidents[0]
    
    # 1. Sequence Order Fidelity
    reconstructed_event_ids = [e.get("event_id") for e in inc.get("ordered_events", [])]
    gt_order = gt["order"]
    
    # Filter to events present in both
    common_events = [eid for eid in gt_order if eid in reconstructed_event_ids]
    
    gt_ranks = [gt_order.index(eid) for eid in common_events]
    rec_ranks = [reconstructed_event_ids.index(eid) for eid in common_events]
    
    if len(common_events) >= 2:
        tau, p_val = kendalltau(gt_ranks, rec_ranks)
        if tau is None or (hasattr(tau, "__len__") and len(tau) == 0):
            tau = 1.0
    else:
        tau = 1.0
        
    # Order inversion count
    inversions = 0
    total_pairs = 0
    for i in range(len(common_events)):
        for j in range(i + 1, len(common_events)):
            total_pairs += 1
            if (rec_ranks[i] > rec_ranks[j]) != (gt_ranks[i] > gt_ranks[j]):
                inversions += 1
                
    order_accuracy_pct = round(((total_pairs - inversions) / total_pairs * 100.0) if total_pairs > 0 else 100.0, 2)
    
    # 2. Entity Identification (Precision, Recall, F1)
    rec_users = {inc.get("affected_user")} if inc.get("affected_user") else set()
    rec_devices = set(inc.get("affected_devices", []))
    rec_apps = set(inc.get("applications", []))
    rec_network = set(inc.get("network_entities", []))
    
    rec_all_entities = rec_users | rec_devices | rec_apps | rec_network
    gt_all_entities = (
        gt["entities"]["users"] |
        gt["entities"]["devices"] |
        gt["entities"]["applications"] |
        gt["entities"]["network_entities"]
    )
    
    tp_entities = len(rec_all_entities & gt_all_entities)
    fp_entities = len(rec_all_entities - gt_all_entities)
    fn_entities = len(gt_all_entities - rec_all_entities)
    
    entity_precision = round((tp_entities / (tp_entities + fp_entities)) if (tp_entities + fp_entities) > 0 else 0.0, 4)
    entity_recall = round((tp_entities / (tp_entities + fn_entities)) if (tp_entities + fn_entities) > 0 else 0.0, 4)
    entity_f1 = round((2 * entity_precision * entity_recall / (entity_precision + entity_recall)) if (entity_precision + entity_recall) > 0 else 0.0, 4)
    
    # 3. Patient Zero / Root Cause Accuracy
    # Check if primary threat or root cause points to patient zero event
    major_contributing = inc.get("major_contributing_events", [])
    top_contributor_id = major_contributing[0].get("event_id") if major_contributing else None
    root_cause_text = str(inc.get("root_cause") or inc.get("target") or "").lower()
    
    patient_zero_matched = (
        top_contributor_id == gt["patient_zero_event_id"] or
        gt["patient_zero_target"].lower() in root_cause_text or
        gt["patient_zero_target"].lower() in str(inc.get("target", "")).lower() or
        any(gt["patient_zero_target"].lower() in str(c.get("reason", "")).lower() for c in major_contributing)
    )
    
    # 4. Alert Fatigue Reduction
    raw_alerts = len(events)
    incidents_formed = len(incidents)
    reduction_pct = round(((raw_alerts - incidents_formed) / raw_alerts) * 100.0, 1)
    
    return {
        "scenario_name": name,
        "raw_event_count": raw_alerts,
        "correlated_incidents": incidents_formed,
        "alert_fatigue_reduction_pct": reduction_pct,
        "reconstruction_latency_ms": round(elapsed_ms, 2),
        "sequence_order": {
            "kendall_tau": round(float(tau), 4),
            "pairwise_order_inversions": inversions,
            "total_pairs_evaluated": total_pairs,
            "sequence_fidelity_pct": order_accuracy_pct
        },
        "entity_identification": {
            "ground_truth_entities_count": len(gt_all_entities),
            "reconstructed_entities_count": len(rec_all_entities),
            "true_positives": tp_entities,
            "false_positives": fp_entities,
            "false_negatives": fn_entities,
            "precision": entity_precision,
            "recall": entity_recall,
            "f1_score": entity_f1
        },
        "patient_zero_identification": {
            "expected_patient_zero": gt["patient_zero_target"],
            "reconstructed_root_cause": inc.get("target") or inc.get("root_cause"),
            "correctly_identified": patient_zero_matched
        },
        "loss_assessment_reconstructed": inc.get("loss_assessment") is not None
    }


def run_all_reconstruction_benchmarks() -> Dict[str, Any]:
    """Runs reconstruction evaluation across all 3 ground-truth attack scenarios."""
    print("=" * 70)
    print("CYBERTHREAT AI: INCIDENT RECONSTRUCTION GROUND-TRUTH BENCHMARK")
    print("=" * 70)
    
    base_time = datetime(2026, 10, 15, 14, 0, 0, tzinfo=timezone.utc)
    scenarios = [
        create_phishing_to_c2_scenario(base_time),
        create_credential_abuse_scenario(base_time),
        create_ransomware_scenario(base_time)
    ]
    
    reconstructor = IncidentReconstructor(time_window_seconds=1800, risk_threshold=35.0)
    
    results = []
    for sc in scenarios:
        res = evaluate_scenario_reconstruction(sc, reconstructor)
        results.append(res)
        print(f"\n[-] {res['scenario_name']}")
        print(f"    • Sequence Order Fidelity: {res['sequence_order']['sequence_fidelity_pct']}% (Kendall's tau: {res['sequence_order']['kendall_tau']})")
        print(f"    • Entity Identification: Precision={res['entity_identification']['precision']}, Recall={res['entity_identification']['recall']}, F1={res['entity_identification']['f1_score']}")
        print(f"    • Patient Zero Match: {'SUCCESS' if res['patient_zero_identification']['correctly_identified'] else 'FAILED'}")
        print(f"    • Alert Reduction: {res['alert_fatigue_reduction_pct']}% ({res['raw_event_count']} alerts -> {res['correlated_incidents']} incident)")
        print(f"    • Processing Latency: {res['reconstruction_latency_ms']} ms")
        
    # Aggregate statistics
    mean_fidelity = round(sum(r["sequence_order"]["sequence_fidelity_pct"] for r in results) / len(results), 2)
    mean_tau = round(sum(r["sequence_order"]["kendall_tau"] for r in results) / len(results), 3)
    mean_f1 = round(sum(r["entity_identification"]["f1_score"] for r in results) / len(results), 3)
    mean_reduction = round(sum(r["alert_fatigue_reduction_pct"] for r in results) / len(results), 1)
    patient_zero_acc = round(sum(1 for r in results if r["patient_zero_identification"]["correctly_identified"]) / len(results) * 100.0, 1)
    
    summary = {
        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_scenarios_evaluated": len(results),
        "mean_sequence_order_fidelity_pct": mean_fidelity,
        "mean_kendall_tau": mean_tau,
        "mean_entity_f1_score": mean_f1,
        "patient_zero_identification_accuracy_pct": patient_zero_acc,
        "mean_alert_fatigue_reduction_pct": mean_reduction,
        "scenarios": results
    }
    
    print("\n" + "=" * 70)
    print("BENCHMARK AGGREGATE SUMMARY:")
    print(f"  • Overall Sequence Order Fidelity: {mean_fidelity}% (tau={mean_tau})")
    print(f"  • Overall Entity Identification F1: {mean_f1}")
    print(f"  • Patient Zero Identification Accuracy: {patient_zero_acc}%")
    print(f"  • Mean Alert Fatigue Reduction: {mean_reduction}%")
    print("=" * 70)
    
    with open("experiments/reconstruction_benchmark_results.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved benchmark results to experiments/reconstruction_benchmark_results.json")
    
    return summary


if __name__ == "__main__":
    run_all_reconstruction_benchmarks()
