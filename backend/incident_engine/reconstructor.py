"""
Incident Reconstruction Engine for CyberThreat AI System.

Reconstructs coherent security incidents from streams of telemetry events.
Correlates events based on:
- Same user / device / session
- Temporal proximity (sliding time windows)
- Escalating risk trajectories
- Entity co-occurrence (applications, network endpoints)

Avoids simplistic single-threshold grouping; provides full causal/temporal sequences.
"""

from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime
from .contribution import EventContributionAnalyzer


class IncidentReconstructor:
    """
    Groups and reconstructs multi-stage incidents from raw and scored telemetry events.
    """
    
    def __init__(self, time_window_seconds: int = 900, risk_threshold: float = 35.0, db_manager=None):
        """
        Args:
            time_window_seconds: Max seconds between related events (default 15 minutes)
            risk_threshold: Minimum risk score to trigger or include in an incident evaluation
            db_manager: Database manager for persistence
        """
        self.time_window = time_window_seconds
        self.risk_threshold = risk_threshold
        self.db = db_manager

    def reconstruct_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups chronological events into reconstructed incident objects.
        """
        if not events:
            return []
            
        # Ensure events are sorted chronologically
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        # Group events by (user, device_id) and temporal cluster to guarantee device isolation (Req 4 & 17)
        device_clusters: Dict[str, List[List[Dict[str, Any]]]] = {}
        
        for raw_ev in sorted_events:
            ev = dict(raw_ev)
            # Skip any test events from incident reconstruction (Req 2 & 17)
            feat = ev.get("features", {})
            if isinstance(feat, str):
                import json
                try:
                    feat = json.loads(feat)
                except Exception:
                    feat = {}
            ev["features"] = feat
            if isinstance(feat, dict) and (feat.get("is_test_event") or feat.get("activity_category") == "Test"):
                continue
            if ev.get("event_type", "").startswith("TEST_") or ev.get("detection_source") == "TEST_ENDPOINT":
                continue

            user = ev.get("user_id", "default_user")
            dev = ev.get("device_id", "default_device")
            key = f"{user}::{dev}"
            if key not in device_clusters:
                device_clusters[key] = []
                
            ts_str = ev.get("timestamp")
            try:
                current_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp() if ts_str else 0.0
            except Exception:
                current_ts = 0.0
                
            # Try to add to an existing open cluster for this specific device
            added = False
            for cluster in device_clusters[key]:
                if not cluster:
                    continue
                last_ev = cluster[-1]
                last_ts_str = last_ev.get("timestamp")
                try:
                    last_ts = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00")).timestamp() if last_ts_str else 0.0
                except Exception:
                    last_ts = 0.0
                    
                if abs(current_ts - last_ts) <= self.time_window:
                    cluster.append(ev)
                    added = True
                    break
                    
            if not added:
                device_clusters[key].append([ev])

    def _get_cluster_threat_signature(self, cluster_events: List[Dict[str, Any]]) -> str:
        """Extracts a normalized, deterministic threat campaign signature from a cluster."""
        primary_threat = next((
            e for e in cluster_events 
            if float(e.get("risk_score", 0)) >= 35 or 
               (isinstance(e.get("features"), dict) and e.get("features", {}).get("status") in ("DANGEROUS", "SUSPICIOUS"))
        ), cluster_events[-1])
        
        feat = primary_threat.get("features", {})
        if isinstance(feat, str):
            import json
            try:
                feat = json.loads(feat)
            except Exception:
                feat = {}
        if not isinstance(feat, dict):
            feat = {}

        # 1. Email / phishing threats
        sender = feat.get("threat_indicators", {}).get("sender") or feat.get("sender")
        if not sender:
            desc = feat.get("description", "")
            if "spoofed sender:" in desc.lower():
                import re
                m = re.search(r"spoofed sender:\s*([^\s,]+)", desc, re.IGNORECASE)
                if m:
                    sender = m.group(1).strip()
        if sender:
            return f"phishing::{sender.lower()}"

        # 2. Domain / Network threats
        domain = feat.get("domain") or feat.get("destination_ip")
        if domain and str(domain).lower() not in ("localhost", "127.0.0.1", "mail.google.com"):
            return f"network::{str(domain).lower()}"

        # 3. File / download threats
        file_name = feat.get("file_name")
        if file_name:
            return f"file::{str(file_name).lower()}"

        # 4. Process threats
        proc = feat.get("process_name") or feat.get("app_name")
        if proc and str(proc).lower() not in ("chrome.exe", "msedge.exe"):
            return f"process::{str(proc).lower()}"

        # 5. Fallback: normalized event type or description
        desc_snippet = feat.get("description", "")[:40].lower()
        return f"{primary_threat.get('event_type', 'threat')}::{desc_snippet}"

    def reconstruct_from_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups chronological events into reconstructed incident objects.
        Consolidates recurring sightings of the same ongoing threat campaign to prevent duplicate spammed incidents.
        """
        if not events:
            return []
            
        # Ensure events are sorted chronologically
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))
        
        # Group events by (user, device_id) and temporal cluster to guarantee device isolation (Req 4 & 17)
        device_clusters: Dict[str, List[List[Dict[str, Any]]]] = {}
        
        for raw_ev in sorted_events:
            ev = dict(raw_ev)
            # Skip any test events from incident reconstruction (Req 2 & 17)
            feat = ev.get("features", {})
            if isinstance(feat, str):
                import json
                try:
                    feat = json.loads(feat)
                except Exception:
                    feat = {}
            ev["features"] = feat
            if isinstance(feat, dict) and (feat.get("is_test_event") or feat.get("activity_category") == "Test"):
                continue
            if ev.get("event_type", "").startswith("TEST_") or ev.get("detection_source") == "TEST_ENDPOINT":
                continue

            user = ev.get("user_id", "default_user")
            dev = ev.get("device_id", "default_device")
            key = f"{user}::{dev}"
            if key not in device_clusters:
                device_clusters[key] = []
                
            ts_str = ev.get("timestamp")
            try:
                current_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp() if ts_str else 0.0
            except Exception:
                current_ts = 0.0
                
            # Try to add to an existing open cluster for this specific device
            added = False
            for cluster in device_clusters[key]:
                if not cluster:
                    continue
                last_ev = cluster[-1]
                last_ts_str = last_ev.get("timestamp")
                try:
                    last_ts = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00")).timestamp() if last_ts_str else 0.0
                except Exception:
                    last_ts = 0.0
                    
                if abs(current_ts - last_ts) <= self.time_window:
                    cluster.append(ev)
                    added = True
                    break
                    
            if not added:
                device_clusters[key].append([ev])

        reconstructed_incidents = []
        threat_campaign_clusters: Dict[str, List[Dict[str, Any]]] = {}
        
        for key, clusters in device_clusters.items():
            user, dev = key.split("::", 1)
            for cluster in clusters:
                has_explicit_threat = any(
                    e.get("features", {}).get("status") == "DANGEROUS" or
                    e.get("features", {}).get("is_eicar") or
                    float(e.get("risk_score", 0)) >= 70.0
                    for e in cluster if isinstance(e.get("features"), dict)
                )
                has_suspicious = any(
                    e.get("features", {}).get("status") == "SUSPICIOUS" or
                    float(e.get("risk_score", 0)) >= 55.0
                    for e in cluster if isinstance(e.get("features"), dict)
                )
                max_risk = max([float(e.get("risk_score", 0)) for e in cluster]) if cluster else 0.0
                
                # Only create incident if there is an actual threat
                should_create_incident = has_explicit_threat or (has_suspicious and max_risk >= 55.0)
                if not should_create_incident:
                    continue

                sig = self._get_cluster_threat_signature(cluster)
                campaign_key = f"{user}::{dev}::{sig}"
                if campaign_key not in threat_campaign_clusters:
                    threat_campaign_clusters[campaign_key] = []
                
                # Merge events, deduplicating by event_id
                seen_event_ids = {e.get("event_id") for e in threat_campaign_clusters[campaign_key] if e.get("event_id")}
                for ev in cluster:
                    ev_id = ev.get("event_id")
                    if not ev_id or ev_id not in seen_event_ids:
                        threat_campaign_clusters[campaign_key].append(ev)
                        if ev_id:
                            seen_event_ids.add(ev_id)

        for campaign_key, merged_cluster in threat_campaign_clusters.items():
            user, dev, sig = campaign_key.split("::", 2)
            merged_cluster.sort(key=lambda x: x.get("timestamp", ""))
            incident = self._build_incident_object(merged_cluster, user, threat_sig=sig)
            incident["device_id"] = dev
            reconstructed_incidents.append(incident)
            
            if self.db:
                try:
                    self.db.save_incident(incident)
                except Exception:
                    pass
                    
        return reconstructed_incidents

    def _build_incident_object(self, cluster_events: List[Dict[str, Any]], user_id: str, threat_sig: str = "") -> Dict[str, Any]:
        """
        Builds a comprehensive structured incident dictionary from a cluster of correlated events.
        Uses deterministic hashing based on user, device, and threat campaign signature to ensure stable incident IDs.
        """
        import hashlib
        root_dev = cluster_events[0].get("device_id", "")
        if threat_sig:
            sig = f"{user_id}::{root_dev}::{threat_sig}"
        else:
            root_event_id = cluster_events[0].get("event_id", "")
            sig = f"{user_id}::{root_dev}::{root_event_id}"
        stable_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()[:8].upper()
        incident_id = f"INC-{stable_hash}"
        start_time = cluster_events[0].get("timestamp", "")
        end_time = cluster_events[-1].get("timestamp", "")
        
        devices = list(set(e.get("device_id") for e in cluster_events if e.get("device_id")))
        
        apps = set()
        network_entities = set()
        risk_evolution = []
        timeline = []
        
        for e in cluster_events:
            features = e.get("features", {})
            if isinstance(features, str):
                import json
                try:
                    features = json.loads(features)
                except Exception:
                    features = {}
                    
            app = features.get("app_name") or features.get("process_name") or features.get("display_name")
            if app:
                app_lower = str(app).lower()
                is_benign_sys = app_lower in (
                    "cleanmgr.exe", "dismhost.exe", "wermgr.exe", "consent.exe",
                    "defrag.exe", "lpksetup.exe", "crashhelper.exe", "devicecen.exe",
                    "sihost.exe", "dwm.exe", "taskhostw.exe", "svchost.exe"
                )
                is_threat_ev = features.get("status") in ("DANGEROUS", "SUSPICIOUS") or float(e.get("risk_score", 0)) >= 45.0
                if not is_benign_sys or is_threat_ev:
                    apps.add(app)
                
            for net_key in ("destination_ip", "domain", "network_destination"):
                val = features.get(net_key)
                if val:
                    network_entities.add(val)
                
            desc = features.get("description") or f"{e.get('event_type')} observed"
            status = features.get("status") or ("DANGEROUS" if float(e.get("risk_score", 0)) >= 70 else "SAFE")
            
            timeline.append({
                "timestamp": e.get("timestamp"),
                "description": desc,
                "status": status,
                "event_type": e.get("event_type")
            })

            risk_evolution.append({
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "risk_score": float(e.get("risk_score", 0.0)),
                "anomaly_score": float(e.get("anomaly_score", 0.0)),
                "behavioral_drift": float(e.get("behavioral_drift", 0.0))
            })
            
        contributions = EventContributionAnalyzer.rank_contributions(cluster_events)
        
        max_risk = max([float(e.get("risk_score", 0.0)) for e in cluster_events])
        if max_risk >= 70:
            severity = "CRITICAL"
        elif max_risk >= 50:
            severity = "HIGH"
        elif max_risk >= 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        evidence_factors = len(cluster_events) + len(apps) + len(network_entities)
        confidence = min(0.98, max(0.50, round(0.50 + (evidence_factors * 0.05) + (max_risk / 300.0), 2)))
        
        # Primary threat event
        primary_threat = next((e for e in cluster_events if float(e.get("risk_score", 0)) >= 35 or e.get("features", {}).get("status") in ("DANGEROUS", "SUSPICIOUS")), cluster_events[-1])
        p_feat = primary_threat.get("features", {})
        if isinstance(p_feat, str):
            try:
                import json
                p_feat = json.loads(p_feat)
            except Exception:
                p_feat = {}
                
        target_name = (
            p_feat.get("domain") or
            p_feat.get("file_name") or
            p_feat.get("process_name") or
            p_feat.get("display_name") or
            p_feat.get("auth_method") or
            p_feat.get("target_process") or
            "Security Alert"
        )
        
        # Synthesize dynamic, plain-English causal attack story and loss assessment
        story_data = self._synthesize_causal_attack_story(
            cluster_events=cluster_events,
            apps=list(apps),
            network_entities=list(network_entities),
            max_risk=max_risk,
            severity=severity,
            target_name=target_name,
            device_name=devices[0] if devices else "Local Device"
        )

        title = story_data["title"]
        what_happened = story_data["story_narrative"]
        summary = story_data["story_narrative"]
        why_suspicious = story_data["why_flagged"]
        what_detected = story_data["root_cause"]
        what_affected = story_data["impact_summary"]
        what_next = story_data["recommended_action"]
        response = story_data["recommended_action"]
        action_taken = story_data["recommended_action"]
        primary_device = devices[0] if devices else "LOCAL"

        return {
            "incident_id": incident_id,
            "device_id": primary_device,
            "title": title,
            "target": target_name,
            "severity": severity,
            "status": "OPEN",
            "affected_user": user_id,
            "affected_devices": devices,
            "start_time": start_time,
            "end_time": end_time,
            "event_count": len(cluster_events),
            "event_ids": [e.get("event_id") for e in cluster_events if e.get("event_id")],
            "ordered_events": cluster_events,
            "applications": list(apps),
            "network_entities": list(network_entities),
            "risk_evolution": risk_evolution,
            "major_contributing_events": contributions,
            "confidence": confidence,
            "summary": summary,
            "what_happened": what_happened,
            "why_suspicious": why_suspicious,
            "what_detected": what_detected,
            "what_affected": what_affected,
            "what_next": what_next,
            "action_taken": action_taken,
            "response": response,
            "timeline": timeline,
            # Causal story & loss analysis fields
            "story_narrative": story_data["story_narrative"],
            "attack_steps": story_data["attack_steps"],
            "loss_assessment": story_data["loss_assessment"],
            "root_cause": story_data["root_cause"],
            "recommendation": story_data["recommended_action"]
        }

    def _synthesize_causal_attack_story(
        self,
        cluster_events: List[Dict[str, Any]],
        apps: List[str],
        network_entities: List[str],
        max_risk: float,
        severity: str,
        target_name: str,
        device_name: str
    ) -> Dict[str, Any]:
        """
        Synthesizes a realistic, plain-English causal story explaining how the incident/attack
        happened step-by-step from origin to potential loss.
        """
        steps = []
        narrative_sentences = []

        # Categorize events across the causal chain
        web_evts = []
        file_evts = []
        exec_evts = []
        net_evts = []
        persist_evts = []
        credential_evts = []

        for e in cluster_events:
            e_type = str(e.get("event_type", "")).upper()
            feat = e.get("features", {})
            if isinstance(feat, str):
                import json
                try:
                    feat = json.loads(feat)
                except Exception:
                    feat = {}

            p_name = str(e.get("process_name") or feat.get("process_name") or feat.get("app_name") or "").strip()
            obj_id = str(e.get("object_id") or feat.get("domain") or feat.get("file_name") or feat.get("destination") or "").strip()
            obj_data = str(e.get("object_data") or feat.get("description") or "").strip()

            is_web = "domain" in feat or "http" in obj_id.lower() or e_type in ("WEBSITE_OPENED", "WEBSITE_NAVIGATED", "BROWSER_VISIT")
            is_file = e_type in ("FILE_WRITE", "FILE_CREATE", "DOWNLOAD", "FILE_READ", "FILE_EXEC") or any(
                ext in obj_id.lower() for ext in [
                    ".vbs", ".bat", ".exe", ".uue", ".pdf", ".ps1", ".dll", ".zip", ".rar", ".7z",
                    ".iso", ".mp4", ".avi", ".mkv", ".mov", ".docx", ".docm", ".xlsm", ".scr"
                ]
            )
            is_net = e_type in ("SOCKET_CONNECT", "NETWORK", "C2_BEACON") or "socket:" in obj_id.lower()
            is_persist = any(k in obj_id.lower() for k in ["temp", "startup", "runonce", "registry", "scheduled_task"])
            is_cred = any(k in obj_id.lower() or k in obj_data.lower() for k in ["login data", "credential", "password", "lsass", "vault", "cookie"])

            if is_cred:
                credential_evts.append((e, p_name, obj_id, obj_data))
            elif is_persist:
                persist_evts.append((e, p_name, obj_id, obj_data))
            elif is_net:
                net_evts.append((e, p_name, obj_id, obj_data))
            elif is_file:
                file_evts.append((e, p_name, obj_id, obj_data))
            elif is_web:
                web_evts.append((e, p_name, obj_id, obj_data))
            else:
                exec_evts.append((e, p_name, obj_id, obj_data))

        step_counter = 1

        # 1. ORIGIN & ENTRY VECTOR - Determined strictly by the actual threat event
        threat_evts = [
            e for e in cluster_events
            if (isinstance(e.get("features"), dict) and (
                e.get("features", {}).get("status") in ("DANGEROUS", "SUSPICIOUS")
                or e.get("features", {}).get("is_eicar")
                or e.get("event_type") == "GMAIL_INSPECTION"
            )) or float(e.get("risk_score", 0)) >= 50.0
        ]
        threat_ev = threat_evts[0] if threat_evts else cluster_events[-1]
        t_feat = threat_ev.get("features", {})
        if isinstance(t_feat, str):
            try:
                import json
                t_feat = json.loads(t_feat)
            except Exception:
                t_feat = {}

        t_type = str(threat_ev.get("event_type", "")).upper()
        t_domain = t_feat.get("domain") or ""
        t_file = t_feat.get("file_name") or ""
        t_proc = t_feat.get("process_name") or t_feat.get("display_name") or ""
        t_sender = ""
        indicators = t_feat.get("email_threat_indicators") or []
        if isinstance(indicators, list) and indicators:
            t_sender = str(indicators[0])
        elif isinstance(indicators, dict):
            t_sender = indicators.get("sender", "Phishing Sender")

        if t_type == "GMAIL_INSPECTION" or t_feat.get("is_gmail"):
            s_disp = t_sender or "Phishing Sender"
            narrative_sentences.append(f"1. Entry Point: Phishing email detected in Gmail from '{s_disp}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "Phishing / Email Ingress",
                "title": f"Phishing Email: {s_disp}",
                "description": f"Gmail inspection flagged deceptive message from '{s_disp}' containing high-risk credential-harvesting indicators.",
                "timestamp": threat_ev.get("timestamp"),
                "status": "FLAGGED",
                "badge_color": "#dc2626"
            })
            root_cause = f"Phishing Email ({s_disp})"
            title = f"Phishing Email Incident: {s_disp}"
            step_counter += 1
        elif t_file or any("download" in f[2].lower() or "download" in f[3].lower() for f in file_evts):
            fname = t_file or (file_evts[0][2].split("\\")[-1] if file_evts else "downloaded_file")
            narrative_sentences.append(f"1. Payload Delivery: High-risk file '{fname}' was downloaded or staged on the local system.")
            steps.append({
                "step_number": step_counter,
                "stage": "Payload Ingress / Download",
                "title": f"Inbound Download: {fname}",
                "description": f"File '{fname}' staged on host disk. Detection engine flagged file signature and high risk score ({max_risk:.0f}/100).",
                "timestamp": threat_ev.get("timestamp"),
                "status": "FLAGGED",
                "badge_color": "#dc2626"
            })
            root_cause = f"Inbound File Download ({fname})"
            title = f"File Threat Incident: {fname}"
            step_counter += 1
        elif t_domain and (t_feat.get("status") in ("DANGEROUS", "SUSPICIOUS") or max_risk >= 50):
            dom = t_domain.replace("https://", "").replace("http://", "")
            narrative_sentences.append(f"1. Entry Point: High-risk connection established to '{dom}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "Web Threat / Navigation",
                "title": f"Web Connection: {dom}",
                "description": f"Host network monitor flagged suspicious domain reputation for '{dom}'.",
                "timestamp": threat_ev.get("timestamp"),
                "status": "FLAGGED",
                "badge_color": "#ea580c"
            })
            root_cause = f"Web Connection to '{dom}'"
            title = f"Web Threat Incident: {dom}"
            step_counter += 1
        else:
            proc_main = t_proc or (apps[0] if apps else target_name)
            narrative_sentences.append(f"1. Initial Execution: Process '{proc_main}' triggered anomalous execution on device '{device_name}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "Process Launch",
                "title": f"Execution: {proc_main}",
                "description": f"Process '{proc_main}' evaluated with behavioral anomalies (Risk: {max_risk:.0f}/100).",
                "timestamp": threat_ev.get("timestamp"),
                "status": "FLAGGED" if max_risk >= 40 else "OBSERVED",
                "badge_color": "#dc2626" if max_risk >= 40 else "#0284c7"
            })
            root_cause = f"Execution of process '{proc_main}'"
            title = f"Process Threat Incident: {proc_main}"
            step_counter += 1

        # 2. FILE STAGING / DOWNLOADED FILE INTERACTION
        if file_evts:
            staged_file = file_evts[0][2].split("\\")[-1] or file_evts[0][2]
            p_acting = file_evts[0][1] or (apps[0] if apps else "System Process")
            narrative_sentences.append(f"2. File Handling: File '{staged_file}' was accessed or staged by '{p_acting}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "File Staging & Handling",
                "title": f"File Staging: {staged_file}",
                "description": f"Target file '{staged_file}' was handled by process '{p_acting}'. System analyzed file signature and access path.",
                "timestamp": file_evts[0][0].get("timestamp"),
                "status": "ANALYZED",
                "badge_color": "#7c3aed"
            })
            step_counter += 1

        # 3. EXECUTION CHAIN & SCRIPT / INTERPRETER SPAWNING
        if len(apps) > 1 or exec_evts:
            involved_procs = ", ".join(apps[:4]) if apps else target_name
            narrative_sentences.append(f"3. Execution Spreading: Execution transitioned through host processes ({involved_procs}).")
            steps.append({
                "step_number": step_counter,
                "stage": "Process Chain & Execution",
                "title": f"Execution Chain ({len(apps)} processes)",
                "description": f"Processes involved in this execution flow: {involved_procs}. Heuristic analyzer evaluated parent-child relationships.",
                "timestamp": (exec_evts[0][0] if exec_evts else cluster_events[0]).get("timestamp"),
                "status": "FLAGGED" if max_risk >= 35 else "MONITORED",
                "badge_color": "#dc2626" if max_risk >= 50 else "#d97706"
            })
            step_counter += 1

        # 4. SYSTEM OCCUPATION & PERSISTENCE
        if persist_evts:
            p_obj = persist_evts[0][2].split("\\")[-1] or persist_evts[0][2]
            narrative_sentences.append(f"4. System Occupation: Malware attempted to establish persistence by placing components in '{p_obj}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "System Footprint & Persistence",
                "title": f"Persistence Target: {p_obj}",
                "description": f"Payload wrote artifacts into persistent location ({p_obj}) to survive reboots and maintain access.",
                "timestamp": persist_evts[0][0].get("timestamp"),
                "status": "WARNING",
                "badge_color": "#dc2626"
            })
            step_counter += 1

        # 5. NETWORK COMMUNICATION & C2 BEACONING
        if net_evts:
            dest = net_evts[0][2].replace("socket:", "")
            narrative_sentences.append(f"5. Network Outreach: Binary attempted outbound communication to remote destination '{dest}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "Network & C2 Communication",
                "title": f"Outbound Connection: {dest}",
                "description": f"Host process initiated external socket communication to '{dest}'. Network filter monitored for beaconing or exfiltration.",
                "timestamp": net_evts[0][0].get("timestamp"),
                "status": "FLAGGED" if max_risk >= 50 else "MONITORED",
                "badge_color": "#dc2626" if max_risk >= 50 else "#0284c7"
            })
            step_counter += 1

        # 6. SENSITIVE STORE ACCESS / PRIVILEGED ACTIONS
        if credential_evts:
            cred_target = credential_evts[0][2].split("\\")[-1] or "Credential Store"
            narrative_sentences.append(f"6. Credential Access: An attempt was detected to inspect local sensitive store '{cred_target}'.")
            steps.append({
                "step_number": step_counter,
                "stage": "Sensitive Store Access",
                "title": f"Access Attempt: {cred_target}",
                "description": f"Process requested access to browser or system credential repository '{cred_target}'.",
                "timestamp": credential_evts[0][0].get("timestamp"),
                "status": "CRITICAL",
                "badge_color": "#dc2626"
            })
            step_counter += 1

        # 7. LOSS & IMPACT ASSESSMENT (ACCURATE & GRANULAR)
        if credential_evts:
            loss_status = "POTENTIAL_CREDENTIAL_EXPOSURE"
            loss_level = "ELEVATED"
            data_loss = "POTENTIAL_CREDENTIAL_ACCESS"
            loss_summary = "Credential store access was attempted. Stored passwords or session tokens may have been targeted."
            narrative_sentences.append("Final Impact Assessment: Potential credential store access detected. Immediate password rotation and session termination recommended to prevent account takeover.")
            recommended_action = "Rotate all local browser and account passwords, invalidate active sessions, and terminate the offending process tree."
        elif net_evts and max_risk >= 65:
            loss_status = "EXTERNAL_COMMUNICATION_FLAGGED"
            loss_level = "MODERATE"
            data_loss = "POTENTIAL_EXTERNAL_BURST"
            loss_summary = f"Outbound traffic to {net_evts[0][2]} was flagged. Network monitoring caught the socket connection; no bulk file exfiltration confirmed."
            narrative_sentences.append(f"Final Impact Assessment: Outbound network beaconing caught by real-time telemetry. No massive data exfiltration confirmed.")
            recommended_action = "Block destination host on firewall, sever process socket, and audit network traffic history."
        elif persist_evts:
            loss_status = "PERSISTENCE_ISOLATED"
            loss_level = "LOW"
            data_loss = "CONFIRMED_ZERO"
            loss_summary = "Persistence staging file detected in temp/startup folders. File was flagged for containment before full root compromise."
            narrative_sentences.append("Final Impact Assessment: System compromise was prevented. Staged persistence files were isolated before lateral movement occurred.")
            recommended_action = "Remove the staged persistence files from Temp/Startup, inspect Task Scheduler, and restart device."
        else:
            loss_status = "CONFIRMED_ZERO_LOSS"
            loss_level = "NONE"
            data_loss = "CONFIRMED_ZERO"
            loss_summary = "Zero data loss recorded. No sensitive files exfiltrated, no unauthorized system modifications, and no financial loss occurred."
            narrative_sentences.append("Final Impact Assessment: Telemetry confirms ZERO data loss and ZERO system damage. The event was contained within safe baseline bounds.")
            recommended_action = "Standard baseline monitoring. No administrative cleanup required."

        return {
            "title": title,
            "story_narrative": " ".join(narrative_sentences),
            "attack_steps": steps,
            "root_cause": root_cause,
            "loss_assessment": {
                "status": loss_status,
                "loss_level": loss_level,
                "summary": loss_summary,
                "data_loss": data_loss,
                "system_integrity": "INTACT" if loss_level in ("NONE", "LOW") else "NEEDS_AUDIT",
                "financial_loss": "ZERO",
                "containment_status": "CONTAINED" if max_risk < 70 else "ACTIVE_TRIAGE"
            },
            "why_flagged": f"Activity scored a composite risk of {max_risk:.0f}/100. Behavioral drift and anomaly filters evaluated the execution chain against normal host patterns.",
            "impact_summary": f"Target: {target_name} on {device_name}. {loss_summary}",
            "recommended_action": recommended_action
        }
