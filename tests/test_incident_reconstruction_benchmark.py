"""
Pytest integration for Priority 1 (Real Monitoring Proof) & Priority 2 (Reconstruction Benchmark).
Ensures all continuous monitoring and ground-truth reconstruction requirements pass in CI/automated runs.
"""

from experiments.verify_real_monitoring_proof import (
    test_1_real_windows_process_enumeration as _run_step1,
    test_2_file_monitor_and_signatures as _run_step2,
    test_3_network_monitor_socket_inspection as _run_step3,
    test_4_persistent_storage_and_date_boundaries as _run_step4,
    test_5_offline_queuing_and_duplicate_free_sync as _run_step5
)
from experiments.evaluate_reconstruction import run_all_reconstruction_benchmarks


def test_priority_1_step1_windows_process_enumeration():
    r = _run_step1()
    assert r["active_processes_count"] > 10
    assert r["adware_detection_verified"] is True


def test_priority_1_step2_file_monitor_and_signatures():
    r = _run_step2()
    assert r["double_extension_detected"] is True
    assert r["eicar_detected"] is True


def test_priority_1_step3_network_monitor_socket_inspection():
    r = _run_step3()
    assert r["live_connections_count"] > 0
    assert r["private_filtering_verified"] is True
    assert r["suspicious_port_alerting_verified"] is True


def test_priority_1_step4_persistent_storage_and_date_boundaries():
    r = _run_step4()
    assert r["persistence_verified"] is True
    assert r["date_isolation_verified"] is True


def test_priority_1_step5_offline_queuing_and_duplicate_free_sync():
    r = _run_step5()
    assert r["event_loss_rate_pct"] == 0.0
    assert r["duplicates_rejected"] == 25


def test_priority_2_ground_truth_incident_reconstruction():
    """Validates that incident reconstruction achieves >=95% sequence order fidelity and >=90% entity recall."""
    summary = run_all_reconstruction_benchmarks()
    assert summary["total_scenarios_evaluated"] == 3
    assert summary["mean_sequence_order_fidelity_pct"] >= 95.0
    assert summary["mean_kendall_tau"] >= 0.90
    assert summary["mean_entity_f1_score"] >= 0.90
    assert summary["patient_zero_identification_accuracy_pct"] == 100.0
    assert summary["mean_alert_fatigue_reduction_pct"] >= 70.0
