"""
Behavioral Digital Twin for CyberThreat AI System.

Learns and maintains a behavioral baseline (profile) for each user,
then detects behavioral drift when new events deviate from the baseline.

The Digital Twin models:
- Normal login hours
- Known devices
- Common applications
- Session durations
- Network destinations
- Activity patterns
"""

import json
import statistics
from datetime import datetime


class BehavioralDigitalTwin:
    """
    Behavioral Digital Twin that learns user behavior baselines
    and detects drift from those baselines.
    """

    def __init__(self, db_manager=None):
        self.db = db_manager
        self.profiles = {}  # user_id -> profile dict

    def load_profile(self, user_id: str, profile: dict):
        """Load a previously stored profile."""
        self.profiles[user_id] = profile

    def get_profile(self, user_id: str) -> dict:
        """Get the current behavioral profile for a user."""
        if user_id in self.profiles:
            return self.profiles[user_id]
        if self.db:
            db_profile = self.db.get_behavior_profile(user_id)
            if db_profile:
                self.profiles[user_id] = db_profile
                return db_profile
        return self._empty_profile()

    def learn_baseline_from_events(self, user_id: str, events: list) -> dict:
        """Learns baseline from a batch of historical/training events."""
        for ev in events:
            self.update_baseline(user_id, ev)
        profile = self.get_profile(user_id)
        if self.db:
            try:
                self.db.upsert_behavior_profile(user_id, profile)
            except Exception:
                pass
        return profile

    def evaluate_event(self, event: dict) -> dict:
        """Evaluates an event for drift and returns structured drift dict."""
        user_id = event.get("user_id", "default_user")
        drift_res = self.calculate_drift(user_id, event)
        # Map component scores to factors
        factors = {
            "time_deviation": drift_res["component_scores"].get("login_time", 0.0),
            "device_deviation": drift_res["component_scores"].get("device", 0.0),
            "app_deviation": drift_res["component_scores"].get("application", 0.0),
            "duration_deviation": drift_res["component_scores"].get("session_duration", 0.0),
            "network_deviation": drift_res["component_scores"].get("network_destination", 0.0),
        }
        return {
            "drift_score": drift_res["total_drift"],
            "factors": factors,
            "deviations": drift_res["deviations"],
            "has_baseline": drift_res["has_baseline"]
        }


    def _empty_profile(self) -> dict:
        """Return an empty baseline profile."""
        return {
            "login_hours": [],
            "known_devices": [],
            "common_applications": [],
            "session_durations": [],
            "network_destinations": [],
            "activity_patterns": {},
            "event_count": 0,
        }

    def update_baseline(self, user_id: str, event: dict):
        """
        Update the behavioral baseline with a new event.
        This incrementally learns what is 'normal' for this user.
        """
        if user_id not in self.profiles:
            self.profiles[user_id] = self._empty_profile()

        profile = self.profiles[user_id]
        features = event.get("features", {})
        event_type = event.get("event_type", "")

        # Update login hours
        login_hour = features.get("login_hour")
        if login_hour is None and event.get("timestamp"):
            try:
                ts_str = str(event["timestamp"])
                if "T" in ts_str:
                    login_hour = int(ts_str.split("T")[1].split(":")[0])
                elif " " in ts_str:
                    login_hour = int(ts_str.split()[1].split(":")[0])
            except Exception:
                login_hour = None

        if login_hour is not None:
            hours = profile["login_hours"]
            if login_hour not in hours:
                hours.append(login_hour)
            # Keep only last 20 unique hours as baseline
            profile["login_hours"] = hours[-20:]

        # Update known devices
        device_id = features.get("device_id", event.get("device_id", ""))
        if device_id and device_id not in profile["known_devices"]:
            profile["known_devices"].append(device_id)

        # Update common applications
        app = features.get("application") or features.get("process_name") or features.get("display_name") or features.get("file_name") or ""
        if app and app not in profile["common_applications"]:
            profile["common_applications"].append(app)

        # Update session durations
        duration = features.get("session_duration_min")
        if duration is None and "duration_seconds" in features:
            try:
                duration = float(features["duration_seconds"]) / 60.0
            except Exception:
                duration = None
        if duration is not None:
            durations = profile["session_durations"]
            durations.append(float(duration))
            # Keep last 50 durations
            profile["session_durations"] = durations[-50:]

        # Update network destinations
        dest = features.get("destination") or features.get("domain") or features.get("remote_ip") or ""
        if dest and dest not in profile["network_destinations"]:
            profile["network_destinations"].append(dest)

        # Update activity patterns (count by event type and hour)
        patterns = profile["activity_patterns"]
        key = f"{event_type}_{login_hour if login_hour is not None else 'unknown'}"
        patterns[key] = patterns.get(key, 0) + 1

        profile["event_count"] += 1

    def calculate_drift(self, user_id: str, event: dict) -> dict:
        """
        Calculate behavioral drift between the current event and
        the user's established behavioral baseline.

        Returns a dict with:
            - total_drift: float 0-100 (overall behavioral deviation)
            - deviations: list of specific deviation descriptions
            - component_scores: dict of individual drift components
        """
        profile = self.get_profile(user_id)
        features = event.get("features", {})
        event_type = event.get("event_type", "")

        deviations = []
        component_scores = {}

        # If no baseline yet (< 3 events), cannot compute drift meaningfully
        if profile["event_count"] < 3:
            return {
                "total_drift": 0.0,
                "deviations": [],
                "component_scores": {},
                "has_baseline": False,
            }

        # 1. Login time drift
        login_hour = features.get("login_hour")
        if login_hour is None and event.get("timestamp"):
            try:
                ts_str = str(event["timestamp"])
                if "T" in ts_str:
                    login_hour = int(ts_str.split("T")[1].split(":")[0])
                elif " " in ts_str:
                    login_hour = int(ts_str.split()[1].split(":")[0])
            except Exception:
                login_hour = None

        if login_hour is not None and profile["login_hours"]:
            if login_hour not in profile["login_hours"]:
                # Calculate how far from the nearest known hour
                min_dist = min(
                    min(abs(login_hour - h), 24 - abs(login_hour - h))
                    for h in profile["login_hours"]
                )
                time_drift = min(min_dist / 12.0 * 100, 100)
                component_scores["login_time"] = time_drift
                if time_drift > 20:
                    deviations.append(
                        f"Login time ({login_hour}:00) differs from baseline "
                        f"hours {profile['login_hours']}"
                    )
            else:
                component_scores["login_time"] = 0

        # 2. Device drift
        device_id = features.get("device_id", event.get("device_id", ""))
        device_lower = str(device_id).lower().strip()
        if device_id and profile["known_devices"]:
            known_devs_lower = [str(d).lower().strip() for d in profile["known_devices"]]
            if device_lower not in known_devs_lower:
                component_scores["device"] = 60
                deviations.append(f"New device detected: {device_id}")
            else:
                component_scores["device"] = 0

        # 3. Application drift
        app = features.get("application") or features.get("process_name") or features.get("display_name") or features.get("file_name") or ""
        app_lower = str(app).lower().strip()
        is_self_verified = features.get("is_self_verified") or ("cyberthreat" in app_lower and ("operations center" in app_lower or "desktop" in app_lower))
        from backend.feature_engineering.extract import FeatureExtractor
        is_standard_known_app = any(k in app_lower for k in FeatureExtractor.KNOWN_APPS)

        if is_self_verified:
            component_scores["application"] = 0
        elif app and profile["common_applications"]:
            known_apps_lower = [str(a).lower().strip() for a in profile["common_applications"]]
            if app_lower not in known_apps_lower:
                if is_standard_known_app:
                    # Verified productivity application: minimal novelty and auto-learn
                    component_scores["application"] = 5
                    profile["common_applications"].append(app)
                else:
                    component_scores["application"] = 50
                    deviations.append(f"New application detected: {app}")
            else:
                component_scores["application"] = 0

        # 4. Session duration drift
        duration = features.get("session_duration_min")
        if duration is None and "duration_seconds" in features:
            try:
                duration = float(features["duration_seconds"]) / 60.0
            except Exception:
                duration = None
        if duration is not None and len(profile["session_durations"]) >= 3:
            mean_dur = statistics.mean(profile["session_durations"])
            std_dur = statistics.stdev(profile["session_durations"]) if len(profile["session_durations"]) > 1 else mean_dur * 0.3
            if std_dur > 0:
                z_score = abs(duration - mean_dur) / std_dur
                dur_drift = min(z_score * 20, 100)
                component_scores["session_duration"] = dur_drift
                if z_score > 2:
                    deviations.append(
                        f"Session duration ({duration} min) differs from "
                        f"baseline mean ({mean_dur:.0f} min)"
                    )
            else:
                component_scores["session_duration"] = 0

        # 5. Network destination drift
        dest = features.get("destination") or features.get("domain") or features.get("remote_ip") or ""
        dest_lower = str(dest).lower().strip()
        is_standard_dest = (
            any(k in dest_lower for k in FeatureExtractor.KNOWN_DESTINATIONS) or
            dest_lower.startswith("192.168.") or
            dest_lower.startswith("10.") or
            dest_lower.startswith("172.16.")
        )
        if dest and profile["network_destinations"]:
            known_dest_lower = [str(d).lower().strip() for d in profile["network_destinations"]]
            if dest_lower not in known_dest_lower:
                if is_standard_dest:
                    component_scores["network_destination"] = 5
                    profile["network_destinations"].append(dest)
                else:
                    component_scores["network_destination"] = 50
                    deviations.append(f"New network destination: {dest}")
            else:
                component_scores["network_destination"] = 0

        # Calculate total drift as weighted average of component scores
        if component_scores:
            weights = {
                "login_time": 0.2,
                "device": 0.25,
                "application": 0.2,
                "session_duration": 0.1,
                "network_destination": 0.25,
            }
            total = 0.0
            weight_sum = 0.0
            for key, score in component_scores.items():
                w = weights.get(key, 0.15)
                total += score * w
                weight_sum += w

            total_drift = total / weight_sum if weight_sum > 0 else 0.0
        else:
            total_drift = 0.0

        return {
            "total_drift": round(total_drift, 2),
            "deviations": deviations,
            "component_scores": component_scores,
            "has_baseline": True,
        }

    def what_changed(self, user_id: str, event: dict) -> list[dict]:
        """
        Compare current activity against the Behavioral Digital Twin.
        Returns a list of detected changes with descriptions.
        """
        drift_result = self.calculate_drift(user_id, event)
        changes = []

        if not drift_result["has_baseline"]:
            return [{"change": "Insufficient baseline data", "detected": False}]

        features = event.get("features", {})
        profile = self.get_profile(user_id)

        # Check each behavioral dimension
        device_id = str(features.get("device_id") or event.get("device_id") or "").strip()
        if device_id and profile["known_devices"]:
            known_devs_lower = [str(d).lower().strip() for d in profile["known_devices"]]
            is_new = device_id.lower() not in known_devs_lower
            changes.append({
                "change": "New device detected" if is_new else "Known device",
                "detected": is_new,
                "detail": device_id,
            })

        app = str(
            features.get("application") or
            features.get("process_name") or
            features.get("display_name") or
            features.get("file_name") or ""
        ).strip()
        if app and profile["common_applications"]:
            known_apps_lower = [str(a).lower().strip() for a in profile["common_applications"]]
            is_new = app.lower() not in known_apps_lower
            changes.append({
                "change": "New application detected" if is_new else "Known application",
                "detected": is_new,
                "detail": app,
            })

        login_hour = features.get("login_hour")
        if login_hour is not None and profile["login_hours"]:
            is_unusual = login_hour not in profile["login_hours"]
            changes.append({
                "change": "Login time differs from baseline" if is_unusual else "Normal login time",
                "detected": is_unusual,
                "detail": f"Hour {login_hour}",
            })

        duration = features.get("session_duration_min")
        if duration is not None and len(profile["session_durations"]) >= 3:
            mean_dur = statistics.mean(profile["session_durations"])
            std_dur = statistics.stdev(profile["session_durations"]) if len(profile["session_durations"]) > 1 else mean_dur * 0.3
            is_unusual = std_dur > 0 and abs(duration - mean_dur) / std_dur > 2
            changes.append({
                "change": "Unusual session duration" if is_unusual else "Normal session duration",
                "detected": is_unusual,
                "detail": f"{duration} min (baseline: {mean_dur:.0f} min)",
            })

        dest = str(
            features.get("destination") or
            features.get("domain") or
            features.get("remote_ip") or ""
        ).strip()
        if dest and profile["network_destinations"]:
            known_dest_lower = [str(d).lower().strip() for d in profile["network_destinations"]]
            is_new = dest.lower() not in known_dest_lower
            changes.append({
                "change": "New network destination detected" if is_new else "Known destination",
                "detected": is_new,
                "detail": dest,
            })

        return changes
