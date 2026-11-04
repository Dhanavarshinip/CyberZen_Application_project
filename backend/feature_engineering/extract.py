"""
Feature Extraction for CyberThreat AI System.

Extracts numerical feature vectors from raw telemetry events
for use by the Isolation Forest anomaly detector.
"""

import hashlib
from datetime import datetime


class FeatureExtractor:
    """Extracts numerical features from raw event dictionaries."""

    # Known device/app registries (used for one-hot-like encoding)
    KNOWN_DEVICES = {"laptop_01", "laptop_02", "workstation_03", "mobile_04"}
    KNOWN_APPS = {
        "email_client", "code_editor", "browser", "vpn_client", "database_tool",
        "chrome", "chrome.exe", "msedge", "msedge.exe", "firefox", "firefox.exe",
        "brave", "brave.exe", "opera", "opera.exe", "code", "code.exe",
        "notepad", "notepad.exe", "notepad++", "notepad++.exe", "sublime_text.exe",
        "explorer.exe", "explorer", "winword.exe", "word", "excel.exe", "excel",
        "powerpnt.exe", "powerpoint", "slack", "slack.exe", "teams.exe", "teams",
        "discord.exe", "discord", "spotify.exe", "spotify", "vlc.exe", "vlc",
        "calc.exe", "calculator", "mspaint.exe", "paint", "taskmgr.exe", "task manager",
        "terminal", "windowsterminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
        "python.exe", "pythonw.exe", "electron.exe", "node.exe", "git.exe",
        "cyberthreat ai operations center.exe", "cyberthreat ai operations center",
        "cyberthreat ai.exe", "cyberthreat_ai.exe", "cyberthreat ai"
    }
    KNOWN_DESTINATIONS = {
        "internal-server.local", "mail.company.local", "git.company.local",
        "google.com", "microsoft.com", "github.com", "apple.com", "youtube.com",
        "youtu.be", "cloudflare.com", "wikipedia.org", "mozilla.org", "amazon.com",
        "python.org", "npmjs.com", "stackoverflow.com", "chatgpt.com", "openai.com",
        "127.0.0.1", "localhost", "::1"
    }

    @classmethod
    def extract(cls, event: dict) -> list[float]:
        """
        Extract a feature vector from an event.

        Features:
        0: login_hour (0-23, normalized to 0-1)
        1: is_known_device (0 or 1)
        2: is_known_application (0 or 1)
        3: session_duration_normalized (minutes / 480, capped at 1)
        4: is_known_destination (0 or 1)
        5: is_business_hours (0 or 1) — hours 8-18
        6: bytes_sent_normalized (0-1, scaled by 100000)
        7: event_type_encoded (LOGIN=0.0, APPLICATION=0.5, NETWORK=1.0)
        """
        features = event.get("features", {})

        # Feature 0: Login hour normalized (parsed from features or ISO timestamp)
        login_hour = features.get("login_hour")
        if login_hour is None and event.get("timestamp"):
            try:
                ts_str = str(event["timestamp"])
                if "T" in ts_str:
                    time_part = ts_str.split("T")[1]
                    login_hour = int(time_part.split(":")[0])
                elif " " in ts_str:
                    login_hour = int(ts_str.split()[1].split(":")[0])
            except Exception:
                login_hour = 12
        if login_hour is None:
            login_hour = 12
        try:
            login_hour = int(login_hour)
        except (ValueError, TypeError):
            login_hour = 12
        hour_norm = max(0.0, min(1.0, login_hour / 23.0))

        # Feature 1: Is known device
        device_id = str(features.get("device_id") or event.get("device_id") or "").lower()
        is_known_device = 1.0 if (
            device_id in cls.KNOWN_DEVICES or
            device_id.startswith("dev_") or
            device_id.startswith("dev-") or
            "laptop" in device_id or
            "workstation" in device_id or
            "desktop" in device_id
        ) else 0.0

        # Feature 2: Is known application
        raw_app = str(
            features.get("application") or
            features.get("process_name") or
            features.get("display_name") or
            features.get("file_name") or ""
        ).lower()
        is_known_app = 1.0 if any(k in raw_app for k in cls.KNOWN_APPS) else 0.0

        # Feature 3: Session duration normalized
        duration = features.get("session_duration_min")
        if duration is None and "duration_seconds" in features:
            try:
                duration = float(features["duration_seconds"]) / 60.0
            except Exception:
                duration = 60.0
        if duration is None:
            duration = 60.0
        try:
            duration = float(duration)
        except (ValueError, TypeError):
            duration = 60.0
        duration_norm = max(0.0, min(duration / 480.0, 1.0))

        # Feature 4: Is known destination
        dest = str(features.get("destination") or features.get("domain") or features.get("remote_ip") or "").lower()
        is_private_ip = dest.startswith("192.168.") or dest.startswith("10.") or dest.startswith("172.16.") or dest in ("127.0.0.1", "localhost", "::1")
        is_known_dest = 1.0 if (any(k in dest for k in cls.KNOWN_DESTINATIONS) or is_private_ip) else 0.0

        # Feature 5: Is business hours (8 AM - 6 PM)
        is_business = 1.0 if 8 <= login_hour <= 18 else 0.0

        # Feature 6: Bytes sent normalized
        bytes_sent = features.get("bytes_sent", 0)
        if isinstance(bytes_sent, str):
            try:
                bytes_sent = float(bytes_sent)
            except (ValueError, TypeError):
                bytes_sent = 0
        bytes_norm = min(bytes_sent / 100000.0, 1.0)

        # Feature 7: Event type encoded
        event_type = str(event.get("event_type", "LOGIN")).upper()
        type_map = {
            "LOGIN": 0.0,
            "TEST_LOGIN": 0.0,
            "APPLICATION": 0.5,
            "APPLICATION_START": 0.5,
            "APPLICATION_CLOSED": 0.5,
            "PROCESS_START": 0.5,
            "FILE_DOWNLOAD": 0.75,
            "WEBSITE_OPENED": 0.25,
            "BROWSER_NAVIGATION": 0.25,
            "GMAIL_INSPECTION": 0.35,
            "NETWORK": 1.0,
            "NETWORK_CONNECTION": 1.0,
        }
        type_encoded = type_map.get(event_type, 0.5)

        return [
            hour_norm,
            is_known_device,
            is_known_app,
            duration_norm,
            is_known_dest,
            is_business,
            bytes_norm,
            type_encoded,
        ]

    extract_features = extract

    @classmethod
    def extract_batch(cls, events: list[dict]) -> list[list[float]]:
        """Extract features from a batch of events."""
        return [cls.extract(e) for e in events]

