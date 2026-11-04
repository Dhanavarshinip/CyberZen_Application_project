"""
Event Contribution Analysis for CyberThreat AI System.

Calculates estimated contribution levels (Low, Medium, High) for events within an incident.
Adheres strictly to research honesty: estimates relative contribution to anomalous pattern
without claiming unverified physical causality.
"""

from typing import Dict, Any, List


class EventContributionAnalyzer:
    """
    Computes estimated contribution of individual events to an incident's overall risk footprint.
    """
    
    @staticmethod
    def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates an individual event's estimated contribution.
        """
        event_id = event.get("event_id", "")
        event_type = event.get("event_type", "generic")
        risk_score = float(event.get("risk_score", 0.0))
        anomaly_score = float(event.get("anomaly_score", 0.0))
        behavioral_drift = float(event.get("behavioral_drift", 0.0))
        timestamp = event.get("timestamp", "")
        
        # Contribution score is a composite of risk, anomaly severity, and drift
        score = (risk_score * 0.5) + (anomaly_score * 0.3) + (behavioral_drift * 0.2)
        score = round(max(0.0, min(100.0, score)), 2)
        
        # Determine qualitative level
        if score >= 65.0 or risk_score >= 70.0:
            level = "High"
        elif score >= 35.0 or risk_score >= 40.0:
            level = "Medium"
        else:
            level = "Low"
            
        # Formulate structured explanation
        reasons = []
        if anomaly_score > 50:
            reasons.append(f"Statistical ML anomaly detected (score: {anomaly_score:.1f})")
        if behavioral_drift > 40:
            reasons.append(f"High behavioral deviation from digital twin baseline ({behavioral_drift:.1f})")
        if event_type in ("privilege_escalation", "data_exfiltration", "persistence_established", "ransomware_activity"):
            reasons.append(f"High-impact event classification '{event_type}'")
        elif event_type in ("unusual_login", "new_device_login", "novel_network_connection"):
            reasons.append(f"Boundary deviation event '{event_type}'")
            
        if not reasons:
            reasons.append("Participating timeline contextual event")
            
        return {
            "event_id": event_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "risk_score": risk_score,
            "anomaly_score": anomaly_score,
            "behavioral_drift": behavioral_drift,
            "contribution_score": score,
            "estimated_contribution": level,
            "reason": "; ".join(reasons)
        }

    @classmethod
    def rank_contributions(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Ranks all events by estimated contribution score in descending order.
        """
        analyzed = [cls.analyze_event(ev) for ev in events]
        return sorted(analyzed, key=lambda x: x["contribution_score"], reverse=True)
