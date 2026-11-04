"""
'What Changed?' Differential Analysis for CyberThreat AI System.

Compares recent behavioral telemetry against the user's learned Digital Twin baseline
to provide explainable, structured differential evidence of anomalies.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class WhatChangedAnalyzer:
    """
    Produces structured differential reports comparing recent user events with digital twin baselines.
    """
    
    def __init__(self, digital_twin=None):
        self.digital_twin = digital_twin

    def analyze_user(self, user_id: str, recent_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Performs 'What Changed?' analysis for a user across all recent activity.
        """
        if not self.digital_twin:
            return {
                "user_id": user_id,
                "baseline_established": False,
                "deviations": [],
                "summary": "Behavioral Digital Twin engine not attached.",
                "analysis_time": datetime.now(timezone.utc).isoformat()
            }
            
        profile = self.digital_twin.get_profile(user_id)
        if not profile or profile.get("event_count", 0) < 3:
            return {
                "user_id": user_id,
                "baseline_established": False,
                "deviations": [],
                "summary": f"Insufficient historical baseline for user {user_id}. Baseline learning requires more observation.",
                "analysis_time": datetime.now(timezone.utc).isoformat()
            }
            
        deviations = []
        
        # Analyze recent events against profile
        seen_devices = set(profile.get("known_devices", []))
        seen_apps = set(profile.get("known_apps", []))
        seen_ips = set(profile.get("known_ips", []))
        typical_hours = set(profile.get("typical_hours", [9, 10, 11, 12, 13, 14, 15, 16, 17]))
        
        observed_new_devices = set()
        observed_new_apps = set()
        observed_new_ips = set()
        off_hours_events = []
        high_drift_events = []
        
        for ev in recent_events:
            drift = float(ev.get("behavioral_drift", 0.0))
            if drift >= 40.0:
                high_drift_events.append(ev)
                
            dev = ev.get("device_id")
            if dev and dev not in seen_devices:
                observed_new_devices.add(dev)
                
            features = ev.get("features", {})
            if isinstance(features, str):
                import json
                try:
                    features = json.loads(features)
                except Exception:
                    features = {}
                    
            app = features.get("app_name") or features.get("process_name")
            if app and app not in seen_apps:
                observed_new_apps.add(app)
                
            ip = features.get("destination_ip") or features.get("ip_address") or features.get("domain")
            if ip and ip not in seen_ips:
                observed_new_ips.add(ip)
                
            ts_str = ev.get("timestamp")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if dt.hour not in typical_hours:
                        off_hours_events.append((dt.hour, ev.get("event_type")))
                except Exception:
                    pass

        # Build structured deviation items
        if observed_new_devices:
            deviations.append({
                "category": "Device Access",
                "change_type": "New Device Detected",
                "severity": "HIGH",
                "baseline_value": list(seen_devices),
                "observed_value": list(observed_new_devices),
                "description": f"User authenticated from previously unobserved device(s): {', '.join(observed_new_devices)}"
            })
            
        if observed_new_apps:
            deviations.append({
                "category": "Application Usage",
                "change_type": "Unusual Binary/Process Execution",
                "severity": "HIGH" if any("powershell" in a.lower() or "cmd" in a.lower() or "mimikatz" in a.lower() for a in observed_new_apps) else "MEDIUM",
                "baseline_value": list(seen_apps)[:5],
                "observed_value": list(observed_new_apps),
                "description": f"Execution of applications outside learned baseline: {', '.join(observed_new_apps)}"
            })
            
        if observed_new_ips:
            deviations.append({
                "category": "Network Traffic",
                "change_type": "Novel Destination Connection",
                "severity": "MEDIUM",
                "baseline_value": list(seen_ips)[:5],
                "observed_value": list(observed_new_ips),
                "description": f"Network egress to uncataloged endpoints: {', '.join(observed_new_ips)}"
            })
            
        if off_hours_events:
            unique_hours = sorted(list(set(h for h, _ in off_hours_events)))
            deviations.append({
                "category": "Temporal Activity",
                "change_type": "Off-Hours Operation",
                "severity": "LOW" if len(off_hours_events) < 3 else "MEDIUM",
                "baseline_value": f"Standard hours: {min(typical_hours):02d}:00 - {max(typical_hours):02d}:00",
                "observed_value": f"Activity recorded at hours: {', '.join(f'{h:02d}:00' for h in unique_hours)}",
                "description": f"Activity detected during atypical operational time windows."
            })
            
        if not deviations:
            summary = f"No significant behavioral deviations observed for user '{user_id}'. Current operations align with digital twin baseline."
        else:
            summary = f"Identified {len(deviations)} structural behavioral deviations from the digital twin baseline for '{user_id}' across {len(recent_events)} telemetry events."
            
        return {
            "user_id": user_id,
            "baseline_established": True,
            "baseline_sample_size": profile.get("event_count", 0),
            "deviations": deviations,
            "summary": summary,
            "analysis_time": datetime.now(timezone.utc).isoformat()
        }
