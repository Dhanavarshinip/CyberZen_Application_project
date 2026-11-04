"""
Pytest integration for Priority 3 (Threat Evolution Prediction) and Priority 4 (Deep Autoencoder & RL Q-Agent).
"""

from backend.risk_engine.predictor import ThreatEvolutionPredictor
from backend.anomaly_detection.deep_autoencoder import DeepAutoencoderAnomalyDetector
from backend.adaptive_response.q_agent import AdaptiveResponseQLearningAgent
from experiments.evaluate_prediction import run_all_prediction_benchmarks
from experiments.evaluate_deep_autoencoder import run_deep_autoencoder_benchmark
from experiments.evaluate_rl_agent import run_rl_benchmark


def test_priority_3_threat_evolution_predictor():
    """Validates kinematics-based threat evolution prediction derivatives and forecasts."""
    trajectory = [
        {"timestamp": "2026-10-20T10:00:00Z", "risk_score": 15.0, "behavioral_drift": 10.0},
        {"timestamp": "2026-10-20T10:05:00Z", "risk_score": 35.0, "behavioral_drift": 25.0},
        {"timestamp": "2026-10-20T10:10:00Z", "risk_score": 65.0, "behavioral_drift": 50.0}
    ]

    res = ThreatEvolutionPredictor.forecast_trajectory(trajectory)
    assert res["current_risk_score"] == 65.0
    assert res["velocity_per_min"] > 0
    assert len(res["forecasts"]) == 3

    # Horizons 5m, 15m, 30m
    f5 = res["forecasts"][0]
    assert f5["horizon_minutes"] == 5
    assert f5["predicted_risk_score"] > 65.0  # Should project continued escalation


def test_priority_3_prediction_benchmark_metrics():
    """Validates that predictive modeling achieves >=20% error reduction vs reactive baseline."""
    summary = run_all_prediction_benchmarks()
    metrics = summary["evaluation_summary"]
    assert metrics["mean_lead_time_advantage_minutes"] >= 5.0
    assert metrics["directional_escalation_accuracy_pct"] >= 60.0
    assert metrics["mean_mae_at_t15m"]["relative_error_reduction_pct"] >= 20.0


def test_priority_4_deep_autoencoder():
    """Validates PyTorch Deep Autoencoder training and anomaly scoring."""
    import numpy as np
    normal_data = [list(np.random.normal(0.5, 0.1, 10)) for _ in range(30)]
    ae = DeepAutoencoderAnomalyDetector(input_dim=10)
    ae.train(normal_data, epochs=10)
    assert ae.is_trained is True

    # Normal sample
    norm_res = ae.predict_anomaly(normal_data[0])
    assert "anomaly_score" in norm_res

    # Outlier sample
    outlier = [10.0] * 10
    out_res = ae.predict_anomaly(outlier)
    assert out_res["anomaly_score"] > norm_res["anomaly_score"]


def test_priority_4_rl_q_learning_agent():
    """Validates MDP state discretization, Bellman update, and Q-policy selection."""
    agent = AdaptiveResponseQLearningAgent()

    # Discretization
    state = agent.discretize_state(risk_score=85.0, velocity=3.5, blast_radius_entities=4, asset_type="vault")
    assert state == (3, 2, 2, 2)  # Critical, Rapid, Fleet, Vault

    # Action selection
    action = agent.select_action(state, explore=False)
    assert 0 <= action < 5

    # Bellman update
    next_state = (1, 0, 0, 0)
    delta = agent.update_q_value(state, action, reward=50.0, next_state=next_state)
    assert delta >= 0.0

    # Policy recommendation
    rec = agent.recommend_mitigation(risk_score=90.0, velocity=4.0, blast_radius=4, asset_type="vault")
    assert "recommended_action" in rec
    assert rec["is_simulation_safe"] is True


def test_priority_4_rl_agent_benchmark():
    """Validates that the learned Q-Agent outperforms static threshold rules in cumulative reward."""
    summary = run_rl_benchmark()
    q_reward = summary["policy_comparison"]["learned_q_agent"]["mean_cumulative_reward"]
    static_reward = summary["policy_comparison"]["static_rule_threshold_baseline"]["mean_cumulative_reward"]
    assert q_reward > static_reward
