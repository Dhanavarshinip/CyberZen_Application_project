"""
Risk Engine for CyberThreat AI System.

Implements the research risk evolution model:
R(t) = 0.4 * A(t) + 0.4 * B(t) + 0.2 * H(t)

Where:
- A(t) = Anomaly component from Isolation Forest (normalized 0-100)
- B(t) = Behavioral drift from Digital Twin baseline comparison (0-100)
- H(t) = Historical risk calculated as an exponential moving average or windowed average of past risk scores (0-100)

All components remain fully visible and transparent.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class RiskEngine:
    """
    Computes threat risk evolution based on anomaly score, behavioral drift, and historical context.
    """
    
    WEIGHT_ANOMALY = 0.4
    WEIGHT_DRIFT = 0.4
    WEIGHT_HISTORICAL = 0.2
    
    def __init__(self, db_manager=None, decay_factor: float = 0.85):
        """
        Args:
            db_manager: SQLite database manager instance for querying historical risk
            decay_factor: Weight for decaying historical risk over time (0 < decay < 1)
        """
        self.db = db_manager
        self.decay_factor = decay_factor

    def compute_historical_risk(self, user_id: str, device_id: Optional[str] = None, limit: int = 10) -> float:
        """
        Calculates H(t), the historical risk baseline for a user/device.
        Uses exponential decay weighting across recent risk scores.
        """
        if not self.db:
            return 0.0
            
        recent_scores = self.db.get_recent_risk_scores(user_id=user_id, limit=limit)
        if not recent_scores:
            return 0.0
            
        # Exponential moving average with most recent getting highest weight
        weighted_sum = 0.0
        weight_total = 0.0
        current_weight = 1.0
        
        for record in recent_scores:
            score = float(record.get("risk_score", 0.0))
            weighted_sum += score * current_weight
            weight_total += current_weight
            current_weight *= self.decay_factor
            
        return round(weighted_sum / weight_total, 2) if weight_total > 0 else 0.0

    def calculate_risk(
        self,
        anomaly_score: float,
        behavioral_drift: float,
        user_id: str,
        device_id: Optional[str] = None,
        override_historical: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Calculates R(t) = 0.4*A(t) + 0.4*B(t) + 0.2*H(t).
        
        Args:
            anomaly_score: A(t) in range 0-100
            behavioral_drift: B(t) in range 0-100
            user_id: Identifier for user
            device_id: Identifier for device
            override_historical: Optional precomputed historical risk
            
        Returns:
            Dict containing final risk score, components, formula breakdown, and risk level.
        """
        a_t = max(0.0, min(100.0, float(anomaly_score)))
        b_t = max(0.0, min(100.0, float(behavioral_drift)))
        
        if override_historical is not None:
            h_t = max(0.0, min(100.0, float(override_historical)))
        else:
            h_t = self.compute_historical_risk(user_id=user_id, device_id=device_id)
            
        # R(t) = 0.4*A(t) + 0.4*B(t) + 0.2*H(t)
        raw_risk = (
            self.WEIGHT_ANOMALY * a_t +
            self.WEIGHT_DRIFT * b_t +
            self.WEIGHT_HISTORICAL * h_t
        )
        
        risk_score = round(max(0.0, min(100.0, raw_risk)), 2)
        
        # Categorize risk level
        if risk_score >= 80:
            level = "CRITICAL"
        elif risk_score >= 60:
            level = "HIGH"
        elif risk_score >= 35:
            level = "MEDIUM"
        elif risk_score >= 15:
            level = "LOW"
        else:
            level = "BENIGN"
            
        return {
            "risk_score": risk_score,
            "risk_level": level,
            "components": {
                "anomaly_score_A_t": a_t,
                "behavioral_drift_B_t": b_t,
                "historical_risk_H_t": h_t,
                "weight_anomaly": self.WEIGHT_ANOMALY,
                "weight_drift": self.WEIGHT_DRIFT,
                "weight_historical": self.WEIGHT_HISTORICAL
            },
            "formula": f"R(t) = {self.WEIGHT_ANOMALY}*{a_t:.1f} + {self.WEIGHT_DRIFT}*{b_t:.1f} + {self.WEIGHT_HISTORICAL}*{h_t:.1f} = {risk_score:.2f}",
            "calculated_at": datetime.now(timezone.utc).isoformat()
        }
