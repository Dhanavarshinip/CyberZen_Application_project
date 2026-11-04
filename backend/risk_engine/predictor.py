"""
Threat Evolution Predictor for CyberThreat AI System.

Implements forward-looking risk trajectory forecasting:
Given historical risk evolution R(t), computes:
- Velocity v(t) = dR/dt (rate of threat escalation)
- Acceleration a(t) = d^2R/dt^2 (threat momentum change)
- Behavioral drift momentum M(t)
- Forecasted risk R_hat(t + k) for future horizons: k in {5 min, 15 min, 30 min}
- Upper and lower confidence intervals

Adheres strictly to research rigor: provides clear mathematical formulation,
damping factors, and confidence bounds without black-box exaggeration.
"""

import math
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta


class ThreatEvolutionPredictor:
    """
    Predicts evolving cybersecurity risk trajectories across forward time horizons.
    """

    HORIZONS_MINUTES = [5, 15, 30]
    DAMPING_LAMBDA = 0.04  # Temporal friction damping factor

    def __init__(self, db_manager=None):
        self.db = db_manager

    @classmethod
    def calculate_derivatives(cls, trajectory: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Computes velocity dR/dt, acceleration d^2R/dt^2, and drift momentum from past sequence.
        Trajectory items should have 'timestamp', 'risk_score', and optional 'behavioral_drift'.
        """
        if not trajectory or len(trajectory) < 2:
            return {
                "current_risk": float(trajectory[-1].get("risk_score", 0.0)) if trajectory else 0.0,
                "velocity_per_min": 0.0,
                "acceleration_per_min2": 0.0,
                "drift_momentum": 0.0,
                "data_points": len(trajectory)
            }

        # Parse timestamps into minutes relative to first point
        points = []
        for p in trajectory:
            ts_str = p.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                t_sec = dt.timestamp()
            except Exception:
                t_sec = 0.0
            r = float(p.get("risk_score", 0.0))
            b = float(p.get("behavioral_drift", 0.0))
            points.append((t_sec, r, b))

        # Sort chronologically
        points.sort(key=lambda x: x[0])

        current_risk = points[-1][1]

        # Velocity between last two distinct points
        t_last, r_last, b_last = points[-1]
        t_prev, r_prev, b_prev = points[-2]
        dt_min = (t_last - t_prev) / 60.0

        if dt_min <= 0.01:
            dt_min = 1.0  # Fallback 1 minute interval if timestamps are identical

        v_curr = (r_last - r_prev) / dt_min
        db_curr = (b_last - b_prev) / dt_min

        # Acceleration if at least 3 points available
        a_curr = 0.0
        if len(points) >= 3:
            t_pprev, r_pprev, _ = points[-3]
            dt_prev_min = (t_prev - t_pprev) / 60.0
            if dt_prev_min <= 0.01:
                dt_prev_min = 1.0
            v_prev = (r_prev - r_pprev) / dt_prev_min
            a_curr = (v_curr - v_prev) / ((dt_min + dt_prev_min) / 2.0)

        # Damp extreme noise
        v_curr = max(-25.0, min(25.0, v_curr))
        a_curr = max(-10.0, min(10.0, a_curr))
        drift_mom = max(-15.0, min(15.0, db_curr * 0.35))

        return {
            "current_risk": current_risk,
            "velocity_per_min": round(v_curr, 4),
            "acceleration_per_min2": round(a_curr, 4),
            "drift_momentum": round(drift_mom, 4),
            "data_points": len(points)
        }

    @classmethod
    def forecast_trajectory(
        cls,
        trajectory: List[Dict[str, Any]],
        horizons_minutes: Optional[List[int]] = None
    ) -> Dict[str, Any]:
        """
        Produces multi-horizon predictive risk forecasts:
        R_hat(t + k) = clip(R(t) + v*k*damping + 0.5*a*k^2*damping_acc + M*k, 0, 100)
        """
        horizons = horizons_minutes or cls.HORIZONS_MINUTES
        derivs = cls.calculate_derivatives(trajectory)
        r0 = derivs["current_risk"]
        v = derivs["velocity_per_min"]
        a = derivs["acceleration_per_min2"]
        m = derivs["drift_momentum"]

        forecasts = []
        for k in horizons:
            # Damping factor: exponential decay prevents unbounded divergence
            damping_v = math.exp(-cls.DAMPING_LAMBDA * k)
            damping_a = math.exp(-cls.DAMPING_LAMBDA * 1.5 * k)

            delta_v = v * k * damping_v
            delta_a = 0.5 * a * (k ** 2) * damping_a
            delta_m = m * (k / 10.0)

            predicted_r = r0 + delta_v + delta_a + delta_m
            predicted_r = max(0.0, min(100.0, predicted_r))

            # Uncertainty spread expands with time horizon sqrt(k)
            ci_spread = min(20.0, max(2.5, 2.5 * math.sqrt(k) + abs(v) * 0.3))
            lower_ci = max(0.0, predicted_r - ci_spread)
            upper_ci = min(100.0, predicted_r + ci_spread)

            # Categorize predicted escalation status
            if predicted_r >= 70.0:
                threat_state = "CRITICAL_ESCALATION"
            elif predicted_r >= 50.0:
                threat_state = "ELEVATED_RISK"
            elif predicted_r - r0 >= 10.0:
                threat_state = "ACCELERATING"
            elif r0 - predicted_r >= 10.0:
                threat_state = "DE_ESCALATING"
            else:
                threat_state = "STABLE"

            forecasts.append({
                "horizon_minutes": k,
                "predicted_risk_score": round(predicted_r, 2),
                "confidence_interval": {
                    "lower_bound": round(lower_ci, 2),
                    "upper_bound": round(upper_ci, 2),
                    "spread": round(ci_spread * 2, 2)
                },
                "delta_from_current": round(predicted_r - r0, 2),
                "threat_state": threat_state
            })

        # General trend direction
        trend_label = "STABLE"
        if v > 0.8:
            trend_label = "ESCALATING"
        elif v < -0.8:
            trend_label = "DE_ESCALATING"

        return {
            "current_risk_score": r0,
            "velocity_per_min": derivs["velocity_per_min"],
            "acceleration_per_min2": derivs["acceleration_per_min2"],
            "drift_momentum": derivs["drift_momentum"],
            "trend_direction": trend_label,
            "forecasts": forecasts,
            "model": "Kinematic Drift Threat Forecaster (KDTF-v1)",
            "formula": "R_hat(t+k) = clip(R(t) + v*k*e^(-lambda*k) + 0.5*a*k^2*e^(-1.5*lambda*k) + M*k, 0, 100)"
        }
