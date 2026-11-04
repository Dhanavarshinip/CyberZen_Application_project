"""
Isolation Forest Anomaly Detection for CyberThreat AI System.

Uses scikit-learn's Isolation Forest to detect anomalous events
based on extracted feature vectors.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from backend.feature_engineering.extract import FeatureExtractor


class AnomalyDetector:
    """Isolation Forest based anomaly detector."""

    def __init__(self, contamination: float = 0.15, random_state: int = 42, n_estimators: int = 100):
        """
        Initialize the anomaly detector.

        Args:
            contamination: Expected proportion of anomalies in training data.
            random_state: Random seed for reproducibility.
            n_estimators: Number of trees in Isolation Forest.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            max_samples="auto",
        )

        self.is_trained = False
        self.feature_extractor = FeatureExtractor()

        # Initialize Supervised Threat Classifier
        self.threat_classifier = None
        try:
            from backend.anomaly_detection.threat_classifier import ThreatClassifier
            tc = ThreatClassifier()
            if tc.is_loaded:
                self.threat_classifier = tc
        except Exception:
            pass

    def train(self, events_or_features):
        """
        Train the Isolation Forest on a list of events or feature vectors.
        """
        if not events_or_features:
            return

        if isinstance(events_or_features[0], list):
            X = np.array(events_or_features)
        else:
            features = FeatureExtractor.extract_batch(events_or_features)
            X = np.array(features)
        self.model.fit(X)
        self.is_trained = True

    def save(self, filepath: str):
        """Persist trained Isolation Forest model to disk."""
        import joblib, os
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        joblib.dump(self.model, filepath)

    def load(self, filepath: str) -> bool:
        """Load pre-trained Isolation Forest model from disk."""
        import joblib, os
        if os.path.exists(filepath):
            try:
                self.model = joblib.load(filepath)
                self.is_trained = True
                return True
            except Exception:
                return False
        return False

    def predict(self, event: dict) -> float:
        """
        Predict the anomaly score for a single event in [0, 1].
        """
        res = self.predict_anomaly(event)
        return res["normalized_score"]

    def predict_anomaly(self, event_or_features) -> dict:
        """
        Evaluates anomaly score for an event or extracted feature vector.
        Returns dict with: raw_score, anomaly_score (0-100), normalized_score (0-1), is_anomaly.
        """
        if isinstance(event_or_features, list):
            features = event_or_features
        else:
            features = FeatureExtractor.extract(event_or_features)
            
        X = np.array([features])
        
        if not self.is_trained:
            norm = self._heuristic_score(features)
            return {
                "raw_score": round(0.5 - norm, 4),
                "normalized_score": norm,
                "anomaly_score": round(norm * 100.0, 2),
                "is_anomaly": norm >= 0.5
            }
            
        raw_score = float(self.model.decision_function(X)[0])
        # Calibrated probability mapping: inliers (raw >= 0) map to low anomaly (<0.35),
        # boundary samples map to ~0.20 - 0.35, true outliers (raw < -0.10) map to high anomaly (>0.50).
        norm = 1.0 / (1.0 + np.exp(raw_score * 12.0 + 1.2))
        norm = round(float(np.clip(norm, 0.0, 1.0)), 4)

        # Multi-model threat fusion with supervised threat classifier
        supervised_prob = 0.0
        threat_factors = []
        if isinstance(event_or_features, dict) and self.threat_classifier and self.threat_classifier.is_loaded:
            threat_res = self.threat_classifier.predict_threat(event_or_features)
            supervised_prob = threat_res.get("threat_probability", 0.0)
            threat_factors = threat_res.get("factors", [])
            if supervised_prob >= 0.60:
                norm = max(norm, supervised_prob)

        return {
            "raw_score": round(raw_score, 4),
            "normalized_score": norm,
            "anomaly_score": round(norm * 100.0, 2),
            "is_anomaly": norm >= 0.5,
            "threat_probability": round(supervised_prob, 4),
            "threat_factors": threat_factors
        }

    def predict_batch(self, events: list[dict]) -> list[float]:
        """Predict anomaly scores for a batch of events."""
        return [self.predict(e) for e in events]

    def _heuristic_score(self, features: list[float]) -> float:
        """
        Calibrated fallback heuristic scoring when model is not trained.
        Avoids penalizing normal evening usage or verified apps.
        """
        score = 0.05  # Verified safe baseline

        if len(features) > 1 and features[1] == 0.0:  # is_known_device
            score += 0.25

        if len(features) > 2 and features[2] == 0.0:  # is_known_app
            score += 0.15

        if len(features) > 4 and features[4] == 0.0:  # is_known_dest
            score += 0.15

        if len(features) > 6 and features[6] > 0.8:  # excessive outbound bytes
            score += 0.20

        return min(round(score, 4), 1.0)


IsolationForestAnomalyDetector = AnomalyDetector

