"""
Threat Evolution Prediction Evaluation Benchmark (Priority 3).

Empirically benchmarks the proposed Kinematic Drift Threat Forecaster against:
1. Baseline 1: Static / Reactive Snapshot Baseline (R_hat(t+k) = R(t))
2. Baseline 2: Unconstrained Linear Extrapolation (R_hat(t+k) = R(t) + v*k)

Evaluation Metrics:
- Mean Absolute Error (MAE) at Horizons T+5m, T+15m, T+30m
- Root Mean Squared Error (RMSE) at Horizons T+5m, T+15m, T+30m
- Directional Escalation Accuracy (DA %)
- Early Warning Lead Time Advantage (minutes prior to critical breach threshold)
"""

import json
import math
import numpy as np
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta

from backend.risk_engine.predictor import ThreatEvolutionPredictor
from backend.collectors.generator import SyntheticTelemetryGenerator


def generate_multi_stage_trajectory(attack_speed: str = "normal") -> List[Dict[str, Any]]:
    """
    Generates a realistic multi-stage evolving threat trajectory:
    Stage 1: Normal activity (Risk: 8-15)
    Stage 2: Reconnaissance & Anomalous Login (Risk: 30-45)
    Stage 3: Privilege Escalation & Execution (Risk: 60-75)
    Stage 4: C2 Egress / Encryption / Exfiltration (Risk: 85-98)
    Stage 5: Post-containment recovery / de-escalation
    """
    interval_min = 3.0 if attack_speed == "fast" else 6.0
    base_t = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)

    # Defined ground truth risk progression
    stages = [
        {"desc": "Normal benign morning traffic", "risk": 10.0, "drift": 8.0, "time_min": 0.0},
        {"desc": "Standard dev tools opened", "risk": 12.5, "drift": 10.0, "time_min": interval_min * 1},
        {"desc": "Off-hours login anomaly", "risk": 34.0, "drift": 28.0, "time_min": interval_min * 2},
        {"desc": "Unusual script process start", "risk": 52.0, "drift": 45.0, "time_min": interval_min * 3},
        {"desc": "Memory access to credential vault", "risk": 74.0, "drift": 68.0, "time_min": interval_min * 4},
        {"desc": "High-volume egress connection", "risk": 91.0, "drift": 88.0, "time_min": interval_min * 5},
        {"desc": "Active exfiltration burst", "risk": 96.0, "drift": 94.0, "time_min": interval_min * 6},
        {"desc": "Automated session isolated", "risk": 82.0, "drift": 70.0, "time_min": interval_min * 7},
        {"desc": "Containment verified", "risk": 45.0, "drift": 35.0, "time_min": interval_min * 8},
        {"desc": "System returned to baseline", "risk": 18.0, "drift": 12.0, "time_min": interval_min * 9},
    ]

    trajectory = []
    for s in stages:
        t = base_t + timedelta(minutes=s["time_min"])
        trajectory.append({
            "timestamp": t.isoformat(),
            "time_minutes": s["time_min"],
            "risk_score": s["risk"],
            "behavioral_drift": s["drift"],
            "description": s["desc"]
        })

    return trajectory


def evaluate_forecasts_across_trajectory(trajectory: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Simulates real-time sliding evaluations across the trajectory.
    At each step i (with history 0..i), forecasts future horizons and evaluates against
    actual ground-truth outcomes occurring at (t + horizon).
    """
    horizons = [5, 15, 30]

    proposed_errors = {h: [] for h in horizons}
    baseline_static_errors = {h: [] for h in horizons}
    baseline_linear_errors = {h: [] for h in horizons}

    directional_matches_proposed = []
    directional_matches_static = []

    # Lead time tracking: when did each model first forecast R >= 70?
    first_forecast_crossing_proposed = None
    actual_crossing_time = None

    # Step through sequence starting from 3 points of history
    for i in range(2, len(trajectory) - 1):
        history = trajectory[:i + 1]
        t_current = history[-1]["time_minutes"]
        r_current = history[-1]["risk_score"]

        # 1. Proposed model forecast
        prediction_result = ThreatEvolutionPredictor.forecast_trajectory(history, horizons_minutes=horizons)
        v = prediction_result["velocity_per_min"]

        # Track early warning lead time
        for f in prediction_result["forecasts"]:
            if f["predicted_risk_score"] >= 70.0 and first_forecast_crossing_proposed is None:
                first_forecast_crossing_proposed = t_current

        # Check against ground truth future points by linear interpolation
        for f in prediction_result["forecasts"]:
            h = f["horizon_minutes"]
            target_t = t_current + h

            # Find actual risk at target_t
            actual_r = None
            for j in range(len(trajectory) - 1):
                t1 = trajectory[j]["time_minutes"]
                t2 = trajectory[j + 1]["time_minutes"]
                if t1 <= target_t <= t2:
                    ratio = (target_t - t1) / (t2 - t1) if (t2 - t1) > 0 else 0
                    actual_r = trajectory[j]["risk_score"] + ratio * (trajectory[j + 1]["risk_score"] - trajectory[j]["risk_score"])
                    break

            if actual_r is None:
                if target_t >= trajectory[-1]["time_minutes"]:
                    actual_r = trajectory[-1]["risk_score"]
                else:
                    continue

            # Model 1: Proposed
            pred_r = f["predicted_risk_score"]
            proposed_errors[h].append(pred_r - actual_r)

            # Baseline 1: Static Naive Snapshot (R_hat = r_current)
            static_r = r_current
            baseline_static_errors[h].append(static_r - actual_r)

            # Baseline 2: Unconstrained Linear (r_current + v*h)
            linear_r = max(0.0, min(100.0, r_current + v * h))
            baseline_linear_errors[h].append(linear_r - actual_r)

            # Directional accuracy: did it correctly predict escalation vs de-escalation?
            actual_delta = actual_r - r_current
            pred_delta = pred_r - r_current
            if abs(actual_delta) >= 2.0:
                is_match = (actual_delta * pred_delta) > 0
                directional_matches_proposed.append(1 if is_match else 0)
                directional_matches_static.append(0)  # Static predicts delta=0 (fails directional test)

    # Find actual crossing time of R >= 70
    for p in trajectory:
        if p["risk_score"] >= 70.0 and actual_crossing_time is None:
            actual_crossing_time = p["time_minutes"]

    lead_time_min = 0.0
    if actual_crossing_time and first_forecast_crossing_proposed:
        lead_time_min = max(0.0, round(actual_crossing_time - first_forecast_crossing_proposed, 1))

    # Calculate metrics
    def calc_stats(err_dict):
        mae = {h: round(float(np.mean(np.abs(err_dict[h]))), 2) for h in horizons if err_dict[h]}
        rmse = {h: round(float(np.sqrt(np.mean(np.square(err_dict[h])))), 2) for h in horizons if err_dict[h]}
        return {"mae": mae, "rmse": rmse}

    proposed_stats = calc_stats(proposed_errors)
    static_stats = calc_stats(baseline_static_errors)
    linear_stats = calc_stats(baseline_linear_errors)

    da_proposed = round((sum(directional_matches_proposed) / len(directional_matches_proposed) * 100.0) if directional_matches_proposed else 0.0, 1)
    da_static = 0.0

    return {
        "trajectory_points_count": len(trajectory),
        "lead_time_advantage_minutes": lead_time_min,
        "directional_escalation_accuracy_pct": {
            "proposed_kinematic_model": da_proposed,
            "baseline_static_reactive": da_static
        },
        "proposed_kinematic_model": proposed_stats,
        "baseline_1_static_reactive": static_stats,
        "baseline_2_unconstrained_linear": linear_stats
    }


def run_all_prediction_benchmarks() -> Dict[str, Any]:
    print("=" * 70)
    print("CYBERTHREAT AI: THREAT EVOLUTION PREDICTION BENCHMARK (PRIORITY 3)")
    print("=" * 70)

    # Run on 3 realistic attack tempos: standard, fast, and multi-stage
    tempos = ["normal", "fast"]
    benchmark_runs = []

    for tempo in tempos:
        traj = generate_multi_stage_trajectory(attack_speed=tempo)
        res = evaluate_forecasts_across_trajectory(traj)
        res["attack_tempo"] = tempo
        benchmark_runs.append(res)

        print(f"\n[-] Attack Tempo: {tempo.upper()}")
        print(f"    • Early Warning Lead Time: +{res['lead_time_advantage_minutes']} minutes ahead of critical breach")
        print(f"    • Directional Accuracy: {res['directional_escalation_accuracy_pct']['proposed_kinematic_model']}% vs Static {res['directional_escalation_accuracy_pct']['baseline_static_reactive']}%")
        print("    • T+5m Horizon:  Proposed MAE=" + str(res["proposed_kinematic_model"]["mae"].get(5)) + " | Static MAE=" + str(res["baseline_1_static_reactive"]["mae"].get(5)))
        print("    • T+15m Horizon: Proposed MAE=" + str(res["proposed_kinematic_model"]["mae"].get(15)) + " | Static MAE=" + str(res["baseline_1_static_reactive"]["mae"].get(15)))

    # Overall Averages across horizons
    avg_mae_proposed = round(float(np.mean([r["proposed_kinematic_model"]["mae"][15] for r in benchmark_runs])), 2)
    avg_mae_static = round(float(np.mean([r["baseline_1_static_reactive"]["mae"][15] for r in benchmark_runs])), 2)
    avg_mae_linear = round(float(np.mean([r["baseline_2_unconstrained_linear"]["mae"][15] for r in benchmark_runs])), 2)
    avg_lead_time = round(float(np.mean([r["lead_time_advantage_minutes"] for r in benchmark_runs])), 1)
    avg_da = round(float(np.mean([r["directional_escalation_accuracy_pct"]["proposed_kinematic_model"] for r in benchmark_runs])), 1)

    improvement_pct = round(((avg_mae_static - avg_mae_proposed) / avg_mae_static) * 100.0, 1)

    summary = {
        "benchmark_timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_summary": {
            "mean_lead_time_advantage_minutes": avg_lead_time,
            "directional_escalation_accuracy_pct": avg_da,
            "mean_mae_at_t15m": {
                "proposed_kinematic_model": avg_mae_proposed,
                "baseline_1_static_reactive": avg_mae_static,
                "baseline_2_unconstrained_linear": avg_mae_linear,
                "relative_error_reduction_pct": improvement_pct
            }
        },
        "tempo_evaluations": benchmark_runs
    }

    print("\n" + "=" * 70)
    print("BENCHMARK AGGREGATE SUMMARY:")
    print(f"  • Proposed Model T+15m MAE: {avg_mae_proposed} (vs Static Baseline MAE: {avg_mae_static})")
    print(f"  • Prediction Error Reduction vs Reactive Baseline: {improvement_pct}%")
    print(f"  • Directional Escalation Accuracy: {avg_da}%")
    print(f"  • Early Warning Lead Time Advantage: +{avg_lead_time} minutes")
    print("=" * 70)

    with open("experiments/prediction_benchmark_results.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved benchmark results to experiments/prediction_benchmark_results.json")

    return summary


if __name__ == "__main__":
    run_all_prediction_benchmarks()
