"""
Synthetic Telemetry Generator for CyberThreat AI System.

Generates controlled synthetic cybersecurity events for research scenarios.
All data is synthetic — no real credentials, no real attacks.
"""

import uuid
import random
from datetime import datetime, timedelta


class EventGenerator:
    """Generates synthetic cybersecurity telemetry events."""

    USERS = ["user_alice", "user_bob", "user_charlie"]
    DEVICES = ["laptop_01", "laptop_02", "workstation_03", "mobile_04"]
    APPLICATIONS = ["email_client", "code_editor", "browser", "vpn_client", "database_tool"]
    NORMAL_DESTINATIONS = ["internal-server.local", "mail.company.local", "git.company.local"]
    SUSPICIOUS_DESTINATIONS = ["unknown-external.example", "suspicious-cdn.example"]
    NORMAL_HOURS = list(range(8, 18))  # 8 AM to 6 PM
    UNUSUAL_HOURS = [2, 3, 4, 23, 0, 1]  # Late night / early morning

    @staticmethod
    def generate_event_id() -> str:
        """Generate unique event ID."""
        return f"evt_{uuid.uuid4().hex[:12]}"

    @classmethod
    def generate_normal_login(cls, user_id: str = None, device_id: str = None,
                               base_time: datetime = None) -> dict:
        """Generate a normal login event during business hours with known device."""
        user = user_id or random.choice(cls.USERS)
        device = device_id or cls.DEVICES[cls.USERS.index(user) % len(cls.DEVICES)]
        ts = base_time or datetime.utcnow().replace(
            hour=random.choice(cls.NORMAL_HOURS),
            minute=random.randint(0, 59)
        )

        return {
            "event_id": cls.generate_event_id(),
            "device_id": device,
            "user_id": user,
            "timestamp": ts.isoformat(),
            "event_type": "LOGIN",
            "features": {
                "login_hour": ts.hour,
                "device_id": device,
                "ip_address": "192.168.1.100",
                "location": "office",
                "auth_method": "password",
                "session_duration_min": random.randint(30, 480),
            },
            "detection_source": "LOCAL",
            "sync_status": "PENDING",
            "created_at": datetime.utcnow().isoformat(),
        }

    @classmethod
    def generate_unusual_login_time(cls, user_id: str = None,
                                     base_time: datetime = None) -> dict:
        """Generate a login event at an unusual hour."""
        user = user_id or random.choice(cls.USERS)
        device = cls.DEVICES[cls.USERS.index(user) % len(cls.DEVICES)]
        ts = base_time or datetime.utcnow().replace(
            hour=random.choice(cls.UNUSUAL_HOURS),
            minute=random.randint(0, 59)
        )

        return {
            "event_id": cls.generate_event_id(),
            "device_id": device,
            "user_id": user,
            "timestamp": ts.isoformat(),
            "event_type": "LOGIN",
            "features": {
                "login_hour": ts.hour,
                "device_id": device,
                "ip_address": "192.168.1.100",
                "location": "remote",
                "auth_method": "password",
                "session_duration_min": random.randint(5, 60),
            },
            "detection_source": "LOCAL",
            "sync_status": "PENDING",
            "created_at": datetime.utcnow().isoformat(),
        }

    @classmethod
    def generate_new_device_event(cls, user_id: str = None,
                                   base_time: datetime = None) -> dict:
        """Generate a login from a new/unknown device."""
        user = user_id or random.choice(cls.USERS)
        new_device = f"unknown_device_{uuid.uuid4().hex[:6]}"
        ts = base_time or datetime.utcnow()

        return {
            "event_id": cls.generate_event_id(),
            "device_id": new_device,
            "user_id": user,
            "timestamp": ts.isoformat(),
            "event_type": "LOGIN",
            "features": {
                "login_hour": ts.hour,
                "device_id": new_device,
                "ip_address": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "location": "unknown",
                "auth_method": "password",
                "session_duration_min": random.randint(5, 120),
            },
            "detection_source": "LOCAL",
            "sync_status": "PENDING",
            "created_at": datetime.utcnow().isoformat(),
        }

    @classmethod
    def generate_application_event(cls, user_id: str = None, app: str = None,
                                    base_time: datetime = None) -> dict:
        """Generate an application usage event."""
        user = user_id or random.choice(cls.USERS)
        device = cls.DEVICES[cls.USERS.index(user) % len(cls.DEVICES)]
        application = app or random.choice(cls.APPLICATIONS)
        ts = base_time or datetime.utcnow()

        return {
            "event_id": cls.generate_event_id(),
            "device_id": device,
            "user_id": user,
            "timestamp": ts.isoformat(),
            "event_type": "APPLICATION",
            "features": {
                "application": application,
                "device_id": device,
                "login_hour": ts.hour,
                "action": "launch",
                "session_duration_min": random.randint(5, 240),
            },
            "detection_source": "LOCAL",
            "sync_status": "PENDING",
            "created_at": datetime.utcnow().isoformat(),
        }

    @classmethod
    def generate_unusual_application_event(cls, user_id: str = None,
                                            base_time: datetime = None) -> dict:
        """Generate an event using an unusual/unknown application."""
        unusual_apps = ["nmap.exe", "wireshark", "unknown_script.py", "powershell_remote"]
        return cls.generate_application_event(
            user_id=user_id,
            app=random.choice(unusual_apps),
            base_time=base_time
        )

    @classmethod
    def generate_network_event(cls, user_id: str = None, destination: str = None,
                                base_time: datetime = None) -> dict:
        """Generate a network connection event."""
        user = user_id or random.choice(cls.USERS)
        device = cls.DEVICES[cls.USERS.index(user) % len(cls.DEVICES)]
        dest = destination or random.choice(cls.NORMAL_DESTINATIONS)
        ts = base_time or datetime.utcnow()

        return {
            "event_id": cls.generate_event_id(),
            "device_id": device,
            "user_id": user,
            "timestamp": ts.isoformat(),
            "event_type": "NETWORK",
            "features": {
                "destination": dest,
                "device_id": device,
                "login_hour": ts.hour,
                "protocol": "HTTPS",
                "bytes_sent": random.randint(100, 50000),
                "bytes_received": random.randint(100, 100000),
                "session_duration_min": random.randint(1, 60),
            },
            "detection_source": "LOCAL",
            "sync_status": "PENDING",
            "created_at": datetime.utcnow().isoformat(),
        }

    @classmethod
    def generate_unusual_network_event(cls, user_id: str = None,
                                        base_time: datetime = None) -> dict:
        """Generate a network event to a suspicious destination."""
        return cls.generate_network_event(
            user_id=user_id,
            destination=random.choice(cls.SUSPICIOUS_DESTINATIONS),
            base_time=base_time
        )

    @classmethod
    def generate_normal_scenario(cls, user_id: str = None) -> list[dict]:
        """Generate a sequence of normal behavior events."""
        user = user_id or "user_alice"
        base = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)
        events = [
            cls.generate_normal_login(user, base_time=base),
            cls.generate_application_event(user, app="email_client", base_time=base + timedelta(minutes=2)),
            cls.generate_application_event(user, app="code_editor", base_time=base + timedelta(minutes=5)),
            cls.generate_network_event(user, destination="git.company.local", base_time=base + timedelta(minutes=10)),
        ]
        return events

    @classmethod
    def generate_suspicious_scenario(cls, user_id: str = None) -> list[dict]:
        """Generate a sequence with suspicious behavior indicators."""
        user = user_id or "user_alice"
        base = datetime.utcnow().replace(hour=3, minute=0, second=0, microsecond=0)
        events = [
            cls.generate_unusual_login_time(user, base_time=base),
            cls.generate_new_device_event(user, base_time=base + timedelta(minutes=2)),
            cls.generate_unusual_application_event(user, base_time=base + timedelta(minutes=4)),
            cls.generate_unusual_network_event(user, base_time=base + timedelta(minutes=6)),
        ]
        return events

    @classmethod
    def generate_multistage_scenario(cls, user_id: str = None) -> list[dict]:
        """
        Generate a full multi-stage attack scenario:
        Normal login → Unusual time → New device → Unusual app → Suspicious network
        """
        user = user_id or "user_alice"
        base = datetime.utcnow().replace(hour=9, minute=0, second=0, microsecond=0)
        events = [
            cls.generate_normal_login(user, base_time=base),
            cls.generate_unusual_login_time(user, base_time=base + timedelta(minutes=2)),
            cls.generate_new_device_event(user, base_time=base + timedelta(minutes=4)),
            cls.generate_unusual_application_event(user, base_time=base + timedelta(minutes=6)),
            cls.generate_unusual_network_event(user, base_time=base + timedelta(minutes=8)),
        ]
        return events

    def generate_normal_telemetry(self, count: int = 10, user_id: str = None) -> list[dict]:
        user = user_id or "user_alice"
        return [self.generate_normal_login(user_id=user) for _ in range(count)]

    def generate_unusual_login_telemetry(self, user_id: str = None) -> list[dict]:
        user = user_id or "user_alice"
        return [self.generate_unusual_login_time(user_id=user)]

    def generate_new_device_telemetry(self, user_id: str = None) -> list[dict]:
        user = user_id or "user_alice"
        return [self.generate_new_device_event(user_id=user)]

    def generate_unusual_application_telemetry(self, user_id: str = None) -> list[dict]:
        user = user_id or "user_alice"
        return [self.generate_unusual_application_event(user_id=user)]

    def generate_novel_network_telemetry(self, user_id: str = None) -> list[dict]:
        user = user_id or "user_alice"
        return [self.generate_unusual_network_event(user_id=user)]

    def generate_multi_stage_attack_telemetry(self, user_id: str = None) -> list[dict]:
        return self.generate_multistage_scenario(user_id=user_id)


SyntheticTelemetryGenerator = EventGenerator

