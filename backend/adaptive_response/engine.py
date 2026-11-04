"""
Adaptive Response Recommendation Engine for CyberThreat AI System.

Generates policy-driven mitigative recommendations based on computed threat risk scores:
- 0–30: Low risk -> Standard Telemetry Monitoring
- 31–60: Moderate risk -> Elevated Sampling & Focused Drift Auditing
- 61–80: High risk -> Re-Authentication / Step-Up MFA Challenge
- 81–100: Critical risk -> Synthetic Session Restriction & Host Isolation

Explicitly labeled as prototype response recommendations to preserve research integrity.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone


class AdaptiveResponseEngine:
    """
    Evaluates incident and event risk footprints to provide recommended containment actions.
    """
    
    TIERS = [
        {
            "min_risk": 81.0,
            "max_risk": 100.0,
            "action_type": "ISOLATE_SESSION",
            "recommended_action": "Synthetic Session Isolation & Credential Revocation",
            "policy_tier": "Tier 4 - High Containment",
            "rationale": "Severe threat risk detected. Immediate automated session containment recommended to prevent lateral progression or exfiltration.",
            "is_automated_executable": True
        },
        {
            "min_risk": 61.0,
            "max_risk": 80.9,
            "action_type": "REQUIRE_MFA",
            "recommended_action": "Enforce Immediate Multi-Factor Re-Authentication",
            "policy_tier": "Tier 3 - Identity Verification Challenge",
            "rationale": "High behavioral drift and anomaly score indicate potential credential compromise or unauthorized access.",
            "is_automated_executable": True
        },
        {
            "min_risk": 31.0,
            "max_risk": 60.9,
            "action_type": "ELEVATE_MONITORING",
            "recommended_action": "Elevate Telemetry Sampling Rate & Drift Tracking",
            "policy_tier": "Tier 2 - Proactive Surveillance",
            "rationale": "Moderate behavioral deviations observed. Increased audit frequency warranted without disrupting normal operations.",
            "is_automated_executable": True
        },
        {
            "min_risk": 0.0,
            "max_risk": 30.9,
            "action_type": "MONITOR",
            "recommended_action": "Maintain Standard Telemetry Monitoring",
            "policy_tier": "Tier 1 - Passive Baseline Observation",
            "rationale": "Telemetry aligns with learned digital twin baselines. No mitigative intervention required.",
            "is_automated_executable": False
        }
    ]

    @classmethod
    def recommend(cls, risk_score: float, incident_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates risk score and generates response recommendation.
        """
        score = max(0.0, min(100.0, float(risk_score)))
        
        matched_tier = cls.TIERS[-1]
        for tier in cls.TIERS:
            if tier["min_risk"] <= score <= tier["max_risk"]:
                matched_tier = tier
                break
                
        # Confidence scaled by context
        confidence = round(0.70 + (score / 350.0), 2)
        
        return {
            "risk_score": score,
            "action_type": matched_tier["action_type"],
            "recommended_action": matched_tier["recommended_action"],
            "policy_tier": matched_tier["policy_tier"],
            "rationale": matched_tier["rationale"],
            "confidence": confidence,
            "is_automated_executable": matched_tier["is_automated_executable"],
            "audit_notes": f"Generated recommendation at {datetime.now(timezone.utc).isoformat()} based on risk score {score:.1f}.",
            "disclaimer": "Prototype response recommendation for research simulation. Non-destructive simulated actions only."
        }
