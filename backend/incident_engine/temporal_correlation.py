"""
Temporal Correlation Engine (TCE) for CyberThreat AI System (SHIELD Module 4).

Implements:
1. Dynamic set integration for threat assessment across sliding time windows
2. Dual-Queue management:
   - Primary Queue (sigma_a >= 0.8): Immediate analyst notification & response
   - Secondary Queue (0.7 <= sigma_a < 0.8): Continued observation of evolving threats
3. Boosting mechanism: Escalates secondary threats when subsequent attack stages manifest
4. Decay mechanism: Gradually decreases confidence of benign one-off anomalies, dropping them when sigma_a < 0.7
5. Rolling memory management: Prunes untagged and resolved graph entities
"""

from typing import Dict, Any, List, Optional
from datetime import datetime


class TemporalCorrelationEngine:
    """
    SHIELD Module 4: Orchestrates cross-window temporal threat tracking,
    boosting multi-stage attacks and decaying spurious anomalies.
    """

    ALERT_THRESHOLD = 0.80
    PRUNE_THRESHOLD = 0.70
    DECAY_RATE = 0.10     # Deducted per consecutive benign window
    BOOST_RATE = 0.15     # Added when corroborating attack stages appear

    def __init__(self, db_manager=None):
        self.db = db_manager
        self.primary_queue: Dict[str, Dict[str, Any]] = {}     # Active high-confidence alerts
        self.secondary_queue: Dict[str, Dict[str, Any]] = {}   # Observed potential developing threats
        self.resolved_attacks: List[Dict[str, Any]] = []

    def process_window_result(self, window_id: str, analysis_result: Dict[str, Any], window_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Integrates results from an LLM Analyzer window into the global attack state.
        """
        confidence = analysis_result.get("confidence_score", 0.0)
        malicious_procs = analysis_result.get("malicious_processes", [])
        stages = analysis_result.get("active_stages", [])

        # Unique key for tracking this process chain
        chain_key = "-".join(sorted(malicious_procs)) if malicious_procs else f"win-{window_id}"

        # 1. Check if this matches a chain already in Secondary Queue -> APPLY BOOSTING
        if chain_key in self.secondary_queue:
            tracked = self.secondary_queue[chain_key]
            # If new stages or new malicious evidence arrived, BOOST score
            previous_stages = set(tracked.get("active_stages", []))
            new_stages = set(stages) - previous_stages

            if new_stages or confidence >= self.ALERT_THRESHOLD:
                boosted_score = min(1.0, tracked["confidence_score"] + self.BOOST_RATE)
                tracked["confidence_score"] = boosted_score
                tracked["active_stages"] = list(previous_stages.union(set(stages)))
                tracked["events"].extend(window_events)
                tracked["last_updated"] = window_id

                if boosted_score >= self.ALERT_THRESHOLD:
                    # Promoted from Secondary to Primary Queue!
                    self.primary_queue[chain_key] = tracked
                    del self.secondary_queue[chain_key]
                    return {
                        "action": "BOOST_PROMOTED_TO_PRIMARY",
                        "chain_key": chain_key,
                        "confidence_score": boosted_score,
                        "message": f"Threat '{chain_key}' escalated to Primary Alert Queue via Boosting (Score: {boosted_score:.2f})."
                    }
                else:
                    return {
                        "action": "BOOSTED_IN_SECONDARY",
                        "chain_key": chain_key,
                        "confidence_score": boosted_score,
                        "message": f"Threat '{chain_key}' confidence increased to {boosted_score:.2f} in Secondary Queue."
                    }

        # 2. Check if this is a brand new detection
        if confidence >= self.ALERT_THRESHOLD:
            self.primary_queue[chain_key] = {
                "chain_key": chain_key,
                "confidence_score": confidence,
                "active_stages": stages,
                "events": window_events,
                "narrative": analysis_result.get("attack_narrative", ""),
                "iocs": analysis_result.get("indicators_of_compromise", []),
                "first_seen": window_id,
                "last_updated": window_id,
                "consecutive_benign_windows": 0
            }
            return {
                "action": "PRIMARY_ALERT_CREATED",
                "chain_key": chain_key,
                "confidence_score": confidence,
                "message": f"High-confidence attack detected: {chain_key} (Score: {confidence:.2f})."
            }

        elif confidence >= self.PRUNE_THRESHOLD:
            self.secondary_queue[chain_key] = {
                "chain_key": chain_key,
                "confidence_score": confidence,
                "active_stages": stages,
                "events": window_events,
                "first_seen": window_id,
                "last_updated": window_id,
                "consecutive_benign_windows": 0
            }
            return {
                "action": "SECONDARY_OBSERVATION_CREATED",
                "chain_key": chain_key,
                "confidence_score": confidence,
                "message": f"Provisional suspicious activity stored in Secondary Queue: {chain_key} (Score: {confidence:.2f})."
            }

        # 3. Apply DECAY to tracked items that received NO supporting evidence in this window
        decay_actions = self._apply_decay_mechanism(current_chain_key=chain_key)

        return {
            "action": "NO_NEW_ALERT",
            "decayed_chains": decay_actions
        }

    def _apply_decay_mechanism(self, current_chain_key: str) -> List[str]:
        """
        Applies Decay to sets that show continued benign behavior in subsequent windows.
        Prunes sets when confidence drops below 0.70 to eliminate alert fatigue.
        """
        pruned = []
        # Check secondary queue
        to_delete = []
        for key, item in self.secondary_queue.items():
            if key != current_chain_key:
                item["consecutive_benign_windows"] = item.get("consecutive_benign_windows", 0) + 1
                item["confidence_score"] -= self.DECAY_RATE
                if item["confidence_score"] < self.PRUNE_THRESHOLD:
                    to_delete.append(key)
                    pruned.append(f"Pruned '{key}' from Secondary Queue (Score decayed below {self.PRUNE_THRESHOLD}).")

        for k in to_delete:
            del self.secondary_queue[k]

        return pruned

    def get_active_threats(self) -> List[Dict[str, Any]]:
        """Returns all confirmed active threats in the primary alert queue."""
        return list(self.primary_queue.values())

    def get_provisional_threats(self) -> List[Dict[str, Any]]:
        """Returns all provisional threats in the secondary observation queue."""
        return list(self.secondary_queue.values())
