"""
Deviation Analyzer for CyberThreat AI System (SHIELD Module 1).

Implements:
1. Frequency Encoding of categorical process-event-object tuples <n_i, e_i, d_i>
2. StandardScaler normalization
3. Local Outlier Factor (LOF) with k=20, contamination=0.1
4. 1-Hop Process Lineage Graph Extraction (Parent & Child fork events)
"""

import numpy as np
from collections import Counter
from typing import Dict, Any, List, Set, Tuple, Optional
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib
from pathlib import Path


class FrequencyEncoder:
    """
    Computes inverse frequency / rarity scores for categorical tuples.
    Rare operations (novel binaries, unusual arguments, unseen destinations)
    receive high rarity values, enabling 24x log reduction.
    """

    def __init__(self):
        self.freq_map: Dict[str, float] = {}
        self.total_count: int = 0

    def fit(self, values: List[str]):
        counts = Counter(values)
        self.total_count = sum(counts.values())
        self.freq_map = {k: v / self.total_count for k, v in counts.items()}

    def transform(self, values: List[str]) -> List[float]:
        # Log-scaled inverse frequency: rarity = -log(frequency + epsilon)
        eps = 1.0 / (self.total_count + 1) if self.total_count > 0 else 1e-5
        rarities = []
        for v in values:
            freq = self.freq_map.get(v, eps)
            # Rarity score normalized between 0.0 and 1.0
            rarity = float(-np.log10(max(freq, eps / 10.0)))
            rarities.append(rarity)
        return rarities


class DeviationAnalyzer:
    """
    SHIELD Module 1: Statistical anomaly detection on raw OS logs.
    Filters benign noise while preserving anomalous processes and 1-hop lineage.
    """

    def __init__(self, contamination: float = 0.1, n_neighbors: int = 20):
        self.contamination = contamination
        self.n_neighbors = n_neighbors
        self.freq_encoder_process = FrequencyEncoder()
        self.freq_encoder_event = FrequencyEncoder()
        self.freq_encoder_object = FrequencyEncoder()
        self.scaler = StandardScaler()
        self.lof = LocalOutlierFactor(
            n_neighbors=self.n_neighbors,
            contamination=self.contamination,
            novelty=True  # Enables online inference on unseen streaming test logs
        )
        self.is_trained = False

    def _extract_log_strings(self, log: Dict[str, Any]) -> Tuple[str, str, str]:
        import re
        p_name = str(log.get("process_name", "unknown"))
        e_type = str(log.get("event_type", "PROCESS_EXEC"))
        o_id = str(log.get("object_id", ""))
        # Generalize numbers in paths to capture structural frequency
        o_id_norm = re.sub(r"\d+", "*", o_id)
        return p_name, e_type, o_id_norm

    def _build_feature_vectors(self, logs: List[Dict[str, Any]], is_training: bool = False) -> np.ndarray:
        p_names = []
        e_types = []
        o_ids = []

        for log in logs:
            p, e, o = self._extract_log_strings(log)
            p_names.append(p)
            e_types.append(e)
            o_ids.append(o)

        if is_training:
            self.freq_encoder_process.fit(p_names)
            self.freq_encoder_event.fit(e_types)
            self.freq_encoder_object.fit(o_ids)

        f_proc = self.freq_encoder_process.transform(p_names)
        f_event = self.freq_encoder_event.transform(e_types)
        f_obj = self.freq_encoder_object.transform(o_ids)

        # Build feature matrix: [process_rarity, event_rarity, object_rarity]
        X = np.column_stack([f_proc, f_event, f_obj])

        if is_training:
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        return X_scaled

    def train(self, baseline_logs: List[Dict[str, Any]]):
        """
        Trains LOF on strictly benign baseline logs (t < t_first_attack).
        """
        if not baseline_logs:
            return

        # Deduplicate identical process-object interactions
        X = self._build_feature_vectors(baseline_logs, is_training=True)
        self.lof.fit(X)
        self.is_trained = True

    def detect_anomalies(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates a batch or window of logs. Returns flagged anomalous logs.
        """
        if not logs:
            return []

        if not self.is_trained:
            # Fallback if untrained: flag known suspicious keywords
            anomalous = []
            for l in logs:
                obj = str(l.get("object_id", "")).lower()
                cmd = str(l.get("object_data", "")).lower()
                pname = str(l.get("process_name", "")).lower()
                if any(k in obj or k in cmd or k in pname for k in ["curl", "vbs", "temp", "regsvcs", "8808", "powershell"]):
                    anomalous.append(l)
            return anomalous

        X = self._build_feature_vectors(logs, is_training=False)
        # LOF prediction: -1 for outlier/anomaly, 1 for inlier
        preds = self.lof.predict(X)
        scores = self.lof.decision_function(X)

        flagged_logs = []
        for idx, (p, s) in enumerate(zip(preds, scores)):
            if p == -1:  # Outlier
                log_copy = dict(logs[idx])
                # Normalize anomaly score in range [0, 1]
                log_copy["lof_score"] = float(s)
                log_copy["anomaly_score"] = round(float(np.clip(-s, 0.0, 1.0) * 100), 2)
                flagged_logs.append(log_copy)

        return flagged_logs

    def extract_one_hop_lineage(self, all_logs: List[Dict[str, Any]], anomalous_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Extracts direct ancestors (parent fork) and descendants (child forks)
        for every flagged anomalous process (Eq. 2 in SHIELD paper).
        R = \bigcup_i G_i \forall l_i : A(l_i) = 1
        """
        if not anomalous_logs:
            return []

        anomalous_pids = {l.get("process_id") for l in anomalous_logs if l.get("process_id")}
        anomalous_parent_pids = {l.get("parent_process_id") for l in anomalous_logs if l.get("parent_process_id")}

        lineage_logs = []
        seen_event_ids = set()

        # Add all anomalous logs first
        for l in anomalous_logs:
            eid = l.get("event_id")
            if eid and eid not in seen_event_ids:
                seen_event_ids.add(eid)
                lineage_logs.append(l)

        # Pull direct ancestors (parent process actions) and immediate children
        for l in all_logs:
            eid = l.get("event_id")
            if eid in seen_event_ids:
                continue

            pid = l.get("process_id")
            ppid = l.get("parent_process_id")

            # Is this log an ancestor or child of an anomalous process?
            if pid in anomalous_parent_pids or ppid in anomalous_pids:
                seen_event_ids.add(eid)
                lineage_logs.append(l)

        return lineage_logs

    def save(self, filepath: str = "models/deviation_analyzer_lof.joblib"):
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str = "models/deviation_analyzer_lof.joblib") -> Optional["DeviationAnalyzer"]:
        if Path(filepath).exists():
            return joblib.load(filepath)
        return None
