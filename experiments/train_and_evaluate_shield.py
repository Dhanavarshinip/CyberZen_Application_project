"""
CyberThreat AI - SHIELD Architecture Training & Evaluation Suite.

Trains and evaluates all 4 SHIELD modules + System Extensions:
1. Module 1: Deviation Analyzer (Frequency Encoding + LOF Outlier Detection + 1-Hop Lineage)
2. Module 2: Graph Analyzer (Initial Infection Sockets + Pruning + Louvain Communities)
3. Module 3: LLM Analyzer (3-Stage Chain-of-Thought + Cyber Kill Chain Mapping + Dual-Queue)
4. Module 4: Temporal Correlation Engine (TCE) (Dynamic Sliding Window + Boosting & Decay)
5. Extension: Multi-Signal Evolving Risk Engine R(t) = 0.4A + 0.4B + 0.2H

Run with: python -m experiments.train_and_evaluate_shield
"""

import time
import json
from pathlib import Path
from typing import Dict, Any, List

from backend.collectors.blind_eagle_dataset import BlindEagleDataset
from backend.anomaly_detection.deviation_analyzer import DeviationAnalyzer
from backend.knowledge_graph.graph_analyzer import GraphAnalyzer
from backend.investigator.shield_llm_analyzer import ShieldLLMAnalyzer
from backend.incident_engine.temporal_correlation import TemporalCorrelationEngine
from backend.risk_engine.calculator import RiskEngine


def run_shield_pipeline():
    print("=" * 80)
    print("  CYBERTHREAT AI - SHIELD APT DETECTION & INTELLIGENT EXPLANATION SUITE")
    print("=" * 80)

    # -------------------------------------------------------------
    # 1. Dataset Generation & Chronological Split (SHIELD Protocol)
    # -------------------------------------------------------------
    print("\n[Phase 1] Preparing Benchmark Dataset (Blind Eagle APT-C-36 Windows Emulation)...")
    generator = BlindEagleDataset()
    train_logs, test_logs = generator.generate_dataset(total_events=6100, split_ratio=0.30)
    print(f"  [+] Total Generated Events: {len(train_logs) + len(test_logs)}")
    print(f"  [+] Chronological Benign Baseline (Train): {len(train_logs)} events (First 30%)")
    print(f"  [+] Multi-Stage Evaluation Window (Test): {len(test_logs)} events (Remaining 70%)")

    # -------------------------------------------------------------
    # 2. Training Deviation Analyzer (Frequency Encoder + LOF)
    # -------------------------------------------------------------
    print("\n[Phase 2] Training Module 1: Deviation Analyzer...")
    start_train = time.perf_counter()
    dev_analyzer = DeviationAnalyzer(contamination=0.10, n_neighbors=20)
    dev_analyzer.train(train_logs)
    dev_analyzer.save("models/deviation_analyzer_lof.joblib")
    train_duration = time.perf_counter() - start_train
    print(f"  [+] Fitted Frequency Encoders for Process, Event, and Object Rarity")
    print(f"  [+] Local Outlier Factor (LOF, k=20, tau=0.1) trained in {train_duration:.3f}s")
    print(f"  [+] Model weights saved to: models/deviation_analyzer_lof.joblib")

    # -------------------------------------------------------------
    # 3. Stream Inference & Sliding Window Evaluation
    # -------------------------------------------------------------
    print("\n[Phase 3] Running Online Sliding Window Stream & Evaluation...")
    graph_analyzer = GraphAnalyzer()
    llm_analyzer = ShieldLLMAnalyzer()
    tce = TemporalCorrelationEngine()
    risk_engine = RiskEngine()

    # Metrics counters
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    window_size = 200
    total_test = len(test_logs)
    num_windows = (total_test + window_size - 1) // window_size

    total_anomalies_flagged = 0
    communities_discovered = 0
    primary_alerts = []

    for w_idx in range(num_windows):
        start_idx = w_idx * window_size
        end_idx = min(start_idx + window_size, total_test)
        window_events = test_logs[start_idx:end_idx]
        window_id = f"W-{w_idx+1:02d}"

        # 1. Deviation Analyzer filters noise & extracts 1-hop lineage
        anomalies = dev_analyzer.detect_anomalies(window_events)
        total_anomalies_flagged += len(anomalies)

        lineage_subgraph = dev_analyzer.extract_one_hop_lineage(window_events, anomalies)

        # 2. Graph Analyzer prunes & clusters into Louvain communities
        communities = graph_analyzer.process(lineage_subgraph)
        communities_discovered += len(communities)

        # 3. LLM Analyzer reasons on each community cluster
        for comm in communities:
            analysis = llm_analyzer.analyze_community(comm)
            tce_result = tce.process_window_result(window_id, analysis, comm)

            if tce_result.get("action") in ("PRIMARY_ALERT_CREATED", "BOOST_PROMOTED_TO_PRIMARY"):
                primary_alerts.append(analysis)

        # Calculate ground truth metrics for this window
        for ev in window_events:
            is_true_atk = ev.get("is_malicious", False)
            # Was this event retained in the filtered lineage/analysis?
            flagged = any(ev.get("event_id") == a.get("event_id") for a in lineage_subgraph)
            
            if is_true_atk and flagged:
                tp += 1
            elif not is_true_atk and flagged:
                fp += 1
            elif not is_true_atk and not flagged:
                tn += 1
            elif is_true_atk and not flagged:
                fn += 1

    # -------------------------------------------------------------
    # 4. Results & Benchmark Metrics
    # -------------------------------------------------------------
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    log_reduction = total_test / total_anomalies_flagged if total_anomalies_flagged > 0 else 1.0

    print("\n" + "=" * 80)
    print("  EVALUATION RESULTS & BENCHMARK METRICS")
    print("=" * 80)
    print(f"  Test Logs Processed:              {total_test}")
    print(f"  Anomalous Logs Flagged by LOF:    {total_anomalies_flagged}")
    print(f"  Log Reduction Factor:             {log_reduction:.2f}x (SHIELD standard: ~20x-24x)")
    print(f"  Louvain Communities Analyzed:     {communities_discovered}")
    print(f"  Confirmed Primary Alerts:         {len(primary_alerts)}")
    print("-" * 80)
    print(f"  Confusion Matrix:")
    print(f"    True Positives (TP):            {tp}")
    print(f"    False Positives (FP):           {fp}")
    print(f"    True Negatives (TN):            {tn}")
    print(f"    False Negatives (FN):           {fn}")
    print("-" * 80)
    print(f"  Precision:                        {precision:.4f} ({precision * 100:.2f}%)")
    print(f"  Recall:                           {recall:.4f} ({recall * 100:.2f}%)")
    print(f"  F1-Score:                         {f1:.4f}")
    print("=" * 80)

    # -------------------------------------------------------------
    # 5. Generated Attack Narrative & Kill Chain Explanation
    # -------------------------------------------------------------
    if primary_alerts:
        best_alert = max(primary_alerts, key=lambda x: x.get("confidence_score", 0))
        print("\n[Generated Natural-Language Attack Narrative - SHIELD Module 3]")
        print(best_alert.get("attack_narrative", ""))
        print("\n[Identified Indicators of Compromise (IoCs)]")
        for ioc in best_alert.get("indicators_of_compromise", []):
            print(f"  - {ioc}")

    # -------------------------------------------------------------
    # 6. Verify User Proposed Extension: Multi-Signal Risk Score
    # -------------------------------------------------------------
    print("\n[Extension Validation] Multi-Signal Evolving Risk Engine:")
    sample_risk = risk_engine.calculate_risk(
        anomaly_score=best_alert.get("confidence_score", 0.85) * 100.0 if primary_alerts else 85.0,
        behavioral_drift=75.0,
        user_id="user_admin",
        device_id="LAPTOP_01"
    )
    print(f"  R(t) = 0.4*A(t) + 0.4*B(t) + 0.2*H(t)")
    print(f"  Calculated Composite Risk Score:  {sample_risk.get('risk_score')}/100 ({sample_risk.get('risk_level')})")
    comps = sample_risk.get('components', {})
    print(f"  Breakdown: A(t)={comps.get('anomaly_score_A_t')}, B(t)={comps.get('behavioral_drift_B_t')}, H(t)={comps.get('historical_risk_H_t')}")
    print("=" * 80)

    # Save summary results
    results_path = "experiments/shield_evaluation_results.json"
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump({
            "test_events": total_test,
            "log_reduction_factor": round(log_reduction, 2),
            "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
            "metrics": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4)
            },
            "primary_alerts_count": len(primary_alerts)
        }, f, indent=2)
    print(f"[+] Full evaluation results written to: {results_path}\n")

if __name__ == "__main__":
    run_shield_pipeline()
