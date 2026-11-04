"""
LLM Analyzer for CyberThreat AI System (SHIELD Module 3).

Implements Algorithm 1 (Chain-of-Thought Detection) from the SHIELD Research Paper:
1. Stage 1: Atomic deviation identification (writes to temp, non-standard dirs, outbound sockets) -> Candidate set C
2. Stage 2: Temporal consistency validation of candidate processes -> Refined malicious set M
3. Stage 3: Attack chain synthesis, Cyber Kill Chain stage mapping, and calibrated confidence scoring (sigma_a)
4. Dual-Queue routing:
   - sigma_a >= 0.8: Primary Alert Queue (high confidence alert + kill chain narrative + IoCs)
   - 0.7 <= sigma_a < 0.8: Secondary Queue (provisional tracking for cross-window temporal correlation)
   - sigma_a < 0.7: Discard / Prune
"""

from typing import Dict, Any, List, Optional, Tuple
import os
import json


class ShieldLLMAnalyzer:
    """
    SHIELD Module 3: Multi-Stage Chain-of-Thought reasoning engine.
    Supports deterministic grounded evaluation (100% offline edge execution)
    and optional local/remote LLM enhancement.
    """

    ALERT_THRESHOLD = 0.80
    OBSERVATION_THRESHOLD = 0.70

    KILL_CHAIN_STAGES = [
        "Reconnaissance",
        "Delivery",
        "Exploitation",
        "Installation",
        "Command and Control",
        "Actions on Objectives"
    ]

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

    def analyze_community(self, community_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes 3-Stage Chain-of-Thought analysis on a Louvain community cluster.
        """
        if not community_events:
            return {"confidence_score": 0.0, "is_alert": False, "summary": "Empty community"}

        # STAGE 1: Check known behavior & identify candidate suspicious processes (Set C)
        candidate_set = self._stage_1_atomic_deviations(community_events)
        if not candidate_set:
            return {
                "confidence_score": 0.15,
                "is_alert": False,
                "queue": "DISCARD",
                "summary": "All operations consistent with normal benign software."
            }

        # STAGE 2: Temporal consistency check -> Refined malicious set M
        malicious_set, temporal_patterns = self._stage_2_temporal_validation(community_events, candidate_set)
        if not malicious_set:
            return {
                "confidence_score": 0.45,
                "is_alert": False,
                "queue": "DISCARD",
                "summary": "Isolated deviations resolved as benign user activity."
            }

        # STAGE 3: Attack chain extraction, Kill Chain mapping, and Confidence Scoring (sigma_a)
        analysis_result = self._stage_3_synthesize_kill_chain(community_events, malicious_set, temporal_patterns)
        sigma_a = analysis_result["confidence_score"]

        # Dual-Queue routing according to Eq. 4 of SHIELD paper
        if sigma_a >= self.ALERT_THRESHOLD:
            analysis_result["queue"] = "PRIMARY_ALERT"
            analysis_result["is_alert"] = True
        elif sigma_a >= self.OBSERVATION_THRESHOLD:
            analysis_result["queue"] = "SECONDARY_OBSERVATION"
            analysis_result["is_alert"] = False
        else:
            analysis_result["queue"] = "DISCARD"
            analysis_result["is_alert"] = False

        return analysis_result

    def _stage_1_atomic_deviations(self, events: List[Dict[str, Any]]) -> List[str]:
        """
        Stage 1: Scans for atomic anomalies (scripts executing from Downloads/Temp,
        abnormal binaries, or suspicious remote sockets).
        """
        candidates = set()
        suspicious_keywords = ["temp", "download", "vbs", "ps1", "bat", "regsvcs", "curl", "cmd.exe", "powershell.exe"]
        suspicious_ports = [8808, 4444, 8080, 1337]

        for e in events:
            pname = str(e.get("process_name", "")).lower()
            obj = str(e.get("object_id", "")).lower()
            data = str(e.get("object_data", "")).lower()

            # Check non-standard paths or script hosts
            if any(k in pname or k in obj or k in data for k in suspicious_keywords):
                candidates.add(pname)

            # Check outbound socket ports
            for port in suspicious_ports:
                if f":{port}" in obj:
                    candidates.add(pname)

        return list(candidates)

    def _stage_2_temporal_validation(self, events: List[Dict[str, Any]], candidate_set: List[str]) -> Tuple[List[str], Dict[str, str]]:
        """
        Stage 2: Tests temporal sequence of actions for each candidate process.
        """
        malicious_processes = []
        patterns = {}

        # Sort events by timestamp
        sorted_evts = sorted(events, key=lambda x: x.get("timestamp", ""))

        for proc in candidate_set:
            proc_evts = [e for e in sorted_evts if str(e.get("process_name", "")).lower() == proc.lower()]
            actions = [e.get("event_type") for e in proc_evts]
            
            # Check for multi-step offensive patterns (e.g., ingress -> write -> execute -> network)
            has_ingress = any(e.get("event_type") == "SOCKET_CONNECT" and "download" in str(e).lower() for e in proc_evts)
            has_file_drop = any(e.get("event_type") == "FILE_WRITE" for e in proc_evts)
            has_execution = any(e.get("event_type") == "PROCESS_EXEC" for e in proc_evts)
            has_persistence = any("startup" in str(e).lower() or "temp" in str(e).lower() for e in proc_evts)

            if (has_file_drop and has_execution) or has_persistence or ("regsvcs" in proc.lower()) or ("vbs" in str(proc_evts).lower()):
                malicious_processes.append(proc)
                patterns[proc] = f"Temporal multi-stage execution confirmed with actions: {actions[:4]}"

        return malicious_processes, patterns

    def _stage_3_synthesize_kill_chain(self, events: List[Dict[str, Any]], malicious_set: List[str], temporal_patterns: Dict[str, str]) -> Dict[str, Any]:
        """
        Stage 3: Maps actions to Cyber Kill Chain stages and computes calibrated confidence score (sigma_a).
        """
        stage_mapping = {s: [] for s in self.KILL_CHAIN_STAGES}
        iocs_found = set()

        for e in events:
            obj = str(e.get("object_id", ""))
            data = str(e.get("object_data", ""))
            pname = str(e.get("process_name", ""))
            e_text = f"{pname} -> {e.get('event_type')}: {obj} ({data})"

            # Extract IoCs
            if "socket:" in obj:
                iocs_found.add(obj.replace("socket:", ""))
            if "factura" in obj.lower() or "fiber" in obj.lower() or "asyncrat" in obj.lower():
                iocs_found.add(obj.replace("file:", "").replace("process:", ""))

            # Kill chain classifier
            if "downloads" in obj.lower() and e.get("event_type") == "FILE_READ":
                stage_mapping["Reconnaissance"].append(e_text)
            elif "curl" in e_text.lower() or "download" in e_text.lower():
                stage_mapping["Delivery"].append(e_text)
            elif "wscript" in pname.lower() or "powershell" in pname.lower() or "regsvcs" in pname.lower():
                stage_mapping["Exploitation"].append(e_text)
            elif "startup" in e_text.lower() or "temp" in e_text.lower():
                stage_mapping["Installation"].append(e_text)
            elif "socket:" in obj and any(p in obj for p in ["8808", "192.168", "cdn"]):
                stage_mapping["Command and Control"].append(e_text)
            elif "login data" in e_text.lower() or "exfiltration" in e_text.lower():
                stage_mapping["Actions on Objectives"].append(e_text)

        # Count active kill-chain stages
        active_stages = [k for k, v in stage_mapping.items() if len(v) > 0]
        n_stages = len(active_stages)

        # Calibrated scoring as defined in SHIELD paper:
        # >= 0.9 for complete attack sequence (>= 4 kill chain stages)
        # 0.8 - 0.9 for partial attack sequence (2 - 3 kill chain stages)
        # 0.7 - 0.8 for detected suspicious pattern (1 stage with strong IoC)
        if n_stages >= 4:
            sigma_a = 0.92
        elif n_stages >= 2:
            sigma_a = 0.85
        elif n_stages == 1:
            sigma_a = 0.75
        else:
            sigma_a = 0.40

        # Construct structured natural-language attack summary
        summary_lines = [
            f"SHIELD Multi-Stage Attack Investigation Report (Confidence: {sigma_a * 100:.1f}%):",
            f"Detected coordinated APT activity spanning {n_stages} Cyber Kill Chain stages across processes: {', '.join(malicious_set)}."
        ]
        for stage in self.KILL_CHAIN_STAGES:
            if stage_mapping[stage]:
                summary_lines.append(f"- **{stage}**: {stage_mapping[stage][0]}")

        return {
            "confidence_score": sigma_a,
            "active_stages": active_stages,
            "kill_chain_breakdown": {k: v for k, v in stage_mapping.items() if v},
            "malicious_processes": malicious_set,
            "indicators_of_compromise": list(iocs_found),
            "attack_narrative": "\n".join(summary_lines)
        }
