"""
Real Host System Monitoring Orchestrator for CyberThreat AI System.

Runs background observation threads collecting genuine system telemetry:
- Live process spawning & execution
- Download directory & file modifications
- Active external network connections
- Browser navigation events from extension
"""

import time
import uuid
import platform
import threading
import ctypes
from typing import Dict, Any, List, Optional, Callable, Set
from datetime import datetime, timezone

from .domain_evaluator import DomainEvaluator
from .file_monitor import FileMonitor
from .process_monitor import ProcessMonitor
from .network_monitor import NetworkMonitor
from .windows_notifier import show_windows_toast, show_threat_alert_popup
from .hardware_id import get_physical_hardware_id

class RealSystemMonitor:
    """Master background coordinator for real-world host telemetry collection."""

    def __init__(self, event_pipeline_callback: Optional[Callable[[Dict[str, Any]], Any]] = None, db_manager=None):
        self.pipeline_cb = event_pipeline_callback
        self.db = db_manager
        self.file_monitor = FileMonitor()
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        self.domain_evaluator = DomainEvaluator()
        
        # Persistent physical hardware identity
        from pathlib import Path
        self.device_id = get_physical_hardware_id()

        usr_file = Path("data") / "local_user_id.txt"
        loaded_uid = ""
        if usr_file.exists():
            try:
                loaded_uid = usr_file.read_text().strip()
            except Exception:
                pass
        self.user_id = loaded_uid if loaded_uid else "current_user"

        now_iso = datetime.now(timezone.utc).isoformat()
        self.metrics = {
            "start_time": time.time(),
            "events_captured_total": 0,
            "events_persisted_total": 0,
            "events_failed_total": 0,
            "events_dropped_total": 0,
            "collector_error_total": 0,
            "last_write_latency_ms": 0.0,
            "sqlite_write_latency": 0.0,
            "cloud_sync_latency": 0.0,
            "duplicate_events_prevented_total": 0,
            "collector_heartbeat_timestamp": now_iso,
            "last_successful_event_timestamp": None,
            "collector_states": {
                "process_monitor": "Active",
                "file_monitor": "Active",
                "network_monitor": "Active",
                "window_monitor": "Active",
                "browser_extension": "Waiting for Events",
                "windows_event_log": "Active"
            }
        }

        self.os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_interval_sec = 2.5  # Responsive polling cadence
        self._notified_domains: Dict[str, float] = {}  # domain -> last notified timestamp
        self._notified_procs: Dict[str, float] = {}  # proc_key -> last notified timestamp
        self._seen_window_titles: Set[str] = set()
        self._last_active_browser_title: str = ""
        self._active_doc_titles: Set[str] = set()
        self._browser_title_last_logged: Dict[str, float] = {}
        self._doc_title_last_logged: Dict[str, float] = {}

    def set_db(self, db):
        self.db = db

    def set_pipeline_callback(self, cb: Callable[[Dict[str, Any]], Any]):
        self.pipeline_cb = cb

    def _emit_event(self, event: Dict[str, Any]):
        """Safely dispatches event to pipeline callback and updates telemetry metrics."""
        if not self.pipeline_cb:
            self.metrics["events_dropped_total"] += 1
            return None
        self.metrics["events_captured_total"] += 1
        t0 = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            res = self.pipeline_cb(event)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self.metrics["last_write_latency_ms"] = round(latency_ms, 2)
            self.metrics["sqlite_write_latency"] = round(latency_ms, 2)
            self.metrics["events_persisted_total"] += 1
            self.metrics["last_successful_event_timestamp"] = now_iso
            self.metrics["collector_heartbeat_timestamp"] = now_iso
            return res
        except Exception as e:
            self.metrics["events_failed_total"] += 1
            self.metrics["collector_error_total"] += 1
            print(f"[-] Pipeline callback error: {e}")
            return None

    def bind_enrolled_device(self, device_id: str, user_id: str, device_name: str = "My Laptop"):
        """Binds the monitor to the authenticated user and enrolled device."""
        self.device_id = device_id
        self.user_id = user_id
        from pathlib import Path
        try:
            (Path("data") / "local_device_id.txt").write_text(device_id)
            (Path("data") / "local_user_id.txt").write_text(user_id)
        except Exception:
            pass
        if self.db and hasattr(self.db, "migrate_unbound_events"):
            try:
                self.db.migrate_unbound_events(new_device_id=device_id, new_user_id=user_id)
            except Exception as e:
                print(f"[-] migrate_unbound_events error: {e}")

    def get_health_metrics(self) -> Dict[str, Any]:
        """Returns comprehensive monitoring health and collector metrics."""
        uptime = int(time.time() - self.metrics["start_time"])
        pending_sync = 0
        if self.db and hasattr(self.db, "get_pending_sync_count"):
            try:
                pending_sync = self.db.get_pending_sync_count()
            except Exception:
                pass
        
        collector_states = dict(self.metrics["collector_states"])
        if not self._running:
            for k in collector_states:
                collector_states[k] = "Inactive"
        else:
            if pending_sync > 0:
                collector_states["sync_engine"] = "Sync Pending"
            else:
                collector_states["sync_engine"] = "Active"

        now_iso = datetime.now(timezone.utc).isoformat()
        heartbeat_ts = self.metrics.get("collector_heartbeat_timestamp") or now_iso

        return {
            "status": "Active" if self._running else "Inactive",
            "monitoring_active": self._running,
            "collector_uptime_seconds": uptime,
            "events_captured_total": self.metrics["events_captured_total"],
            "events_persisted_total": self.metrics["events_persisted_total"],
            "events_failed_total": self.metrics["events_failed_total"],
            "events_dropped_total": self.metrics["events_dropped_total"],
            "collector_error_total": self.metrics.get("collector_error_total", 0),
            "sqlite_write_latency": self.metrics.get("sqlite_write_latency", 0.0),
            "last_write_latency_ms": self.metrics["last_write_latency_ms"],
            "cloud_sync_latency": self.metrics.get("cloud_sync_latency", 0.0),
            "duplicate_events_prevented_total": self.metrics.get("duplicate_events_prevented_total", 0),
            "collector_heartbeat_timestamp": heartbeat_ts,
            "last_successful_event_timestamp": self.metrics.get("last_successful_event_timestamp"),
            "pending_sync_queue_size": pending_sync,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "collector_states": collector_states
        }

    def start(self):
        """Starts background system observation loop."""
        if self._running:
            return
        self._running = True
        
        # Auto-register this device in database on startup
        if self.db:
            try:
                self.db.register_device(
                    device_id=self.device_id,
                    user_id=self.user_id,
                    device_name="My Laptop",
                    os_info=self.os_info
                )
            except Exception:
                pass

        # Emit initial snapshot of currently running apps and active adware
        self._emit_startup_snapshot()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="RealHostMonitorThread")
        self._thread.start()
        print(f"[*] Real-World Host Monitor started on device: {self.device_id} ({self.os_info})")

    def _emit_startup_snapshot(self):
        """
        On startup, emit events for currently running known applications and active adware.
        Alerts user immediately if an adware/promotional popup is already on screen.
        """
        if not self.pipeline_cb:
            return
        try:
            # 1. Check for any active adware/scareware processes on machine
            active_adware = self.process_monitor.find_active_adware_processes()
            for a_info in active_adware:
                ad_name = a_info.get("display_name")
                ad_key = (a_info.get("name") or ad_name).lower()
                self._notified_procs[ad_key] = time.time()
                show_windows_toast(
                    "🟠 CyberThreat AI: Adware / Promotional Ad Detected",
                    f"{ad_name}\nVerdict: Commercial scareware / promotional ad popup.\nSafe from malware, but aggressive upsell alert.",
                    "SUSPICIOUS"
                )
                ev = {
                    "event_id": f"evt_ad_{uuid.uuid4().hex[:10]}",
                    "device_id": self.device_id,
                    "user_id": self.user_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "APPLICATION_START",
                    "features": {
                        "process_name": a_info.get("name"),
                        "display_name": ad_name,
                        "description": f"Adware / Promotional Popup: {ad_name}",
                        "pid": a_info.get("pid"),
                        "exe_path": a_info.get("exe"),
                        "raw_risk": a_info.get("risk_score"),
                        "status": "SUSPICIOUS",
                        "is_adware": True,
                        "activity_category": "Apps",
                        "reasons": a_info.get("reasons", []),
                        "snapshot": True
                    },
                    "detection_source": "REAL_PROCESS_MONITOR"
                }
                self._emit_event(ev)

            # 2. Snapshot currently running interactive desktop applications (e.g. Chrome, VS Code, Notepad, Explorer)
            visible_pids = self.process_monitor.get_visible_window_pids()
            self.process_monitor._seen_pids.update(visible_pids)
            import psutil
            captured_apps = 0
            for pid in visible_pids:
                try:
                    if not psutil.pid_exists(pid):
                        continue
                    proc = psutil.Process(pid)
                    p_info = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'create_time'])
                    name_lower = (p_info.get("name") or "").lower()
                    if self.process_monitor._is_system_noise(name_lower):
                        continue
                    eval_res = self.process_monitor.evaluate_process(p_info)
                    if eval_res.get("is_helper"):
                        continue

                    # If this is CyberThreat AI self-process, register PID to prevent duplicate launch events
                    if eval_res.get("is_self_verified"):
                        from backend.monitoring.self_recognition import _SEEN_SELF_PIDS
                        _SEEN_SELF_PIDS.add(pid)

                    disp_name = eval_res.get("display_name") or eval_res.get("name")
                    create_ts = p_info.get("create_time")
                    try:
                        proc_time_iso = datetime.fromtimestamp(create_ts, tz=timezone.utc).isoformat() if create_ts else datetime.now(timezone.utc).isoformat()
                    except Exception:
                        proc_time_iso = datetime.now(timezone.utc).isoformat()

                    app_event = {
                        "event_id": f"evt_snap_{uuid.uuid4().hex[:10]}",
                        "device_id": self.device_id,
                        "user_id": self.user_id,
                        "timestamp": proc_time_iso,
                        "event_type": "APPLICATION_START",
                        "features": {
                            "process_name": eval_res.get("name"),
                            "display_name": disp_name,
                            "description": f"Active application running: {disp_name}",
                            "pid": pid,
                            "exe_path": eval_res.get("exe"),
                            "cmdline": eval_res.get("cmdline"),
                            "raw_risk": eval_res.get("risk_score", 0.0),
                            "status": eval_res.get("status", "SAFE"),
                            "reasons": eval_res.get("reasons", []),
                            "activity_category": "Apps",
                            "start_time": proc_time_iso,
                            "snapshot": True
                        },
                        "detection_source": "REAL_PROCESS_MONITOR"
                    }
                    self._emit_event(app_event)
                    captured_apps += 1
                except Exception:
                    continue

            print(f"[*] Startup check completed: adware alerts: {len(active_adware)}, active applications snapshot: {captured_apps}.")
        except Exception as e:
            print(f"[-] Startup snapshot failed: {e}")

    def stop(self):
        """Stops background observation loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        print("[*] Real-World Host Monitor stopped.")

    def _get_foreground_window(self) -> Optional[Dict[str, Any]]:
        """
        Retrieves the single top-level window currently in the user's foreground focus.
        Returns dict: {'hwnd': int, 'pid': int, 'proc_name': str, 'title': str} or None.
        """
        if platform.system() != "Windows":
            return None
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd or not user32.IsWindowVisible(hwnd):
                return None
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return None
            buff = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buff, length + 1)
            val = buff.value.strip()
            if not val:
                return None
            pid = ctypes.c_ulong(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            proc_name = ""
            if pid.value:
                try:
                    import psutil
                    proc_name = psutil.Process(pid.value).name()
                except Exception:
                    proc_name = "unknown"
            return {
                "hwnd": hwnd,
                "pid": pid.value,
                "proc_name": proc_name,
                "title": val
            }
        except Exception:
            return None

    def _get_active_desktop_windows(self) -> List[Dict[str, Any]]:
        """
        Enumerates visible top-level windows on the interactive Windows desktop (WinSta0\\default).
        Returns list of dicts: {'hwnd': int, 'pid': int, 'proc_name': str, 'title': str}
        """
        if platform.system() != "Windows":
            return []
        windows = []
        try:
            user32 = ctypes.windll.user32
            hwinsta = user32.OpenWindowStationW("WinSta0", False, 0x037F)
            if hwinsta:
                user32.SetProcessWindowStation(hwinsta)
            hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)

            def enum_proc(hwnd, lParam):
                if user32.IsWindowVisible(hwnd):
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        buff = ctypes.create_unicode_buffer(length + 1)
                        user32.GetWindowTextW(hwnd, buff, length + 1)
                        val = buff.value.strip()
                        if val and val not in ("Program Manager", "Windows Input Experience", "Settings"):
                            pid = ctypes.c_ulong(0)
                            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                            proc_name = ""
                            if pid.value:
                                try:
                                    import psutil
                                    proc_name = psutil.Process(pid.value).name()
                                except Exception:
                                    proc_name = "unknown"
                            windows.append({
                                "hwnd": hwnd,
                                "pid": pid.value,
                                "proc_name": proc_name,
                                "title": val
                            })
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            target = hdesk if hdesk else 0
            if target:
                user32.EnumDesktopWindows(target, WNDENUMPROC(enum_proc), 0)
            else:
                user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
        except Exception:
            pass
        return windows

    def _monitor_loop(self):
        """Main observation loop executing periodic checks."""
        while self._running:
            try:
                # 1. Check for newly downloaded files
                new_files = self.file_monitor.check_new_downloads()
                for f_info in new_files:
                    file_name = f_info.get("file_name", "downloaded_file")
                    status = f_info.get("status", "SAFE")
                    is_eicar = f_info.get("is_eicar_test", False)

                    # Trigger real native Windows notification per device (Req 13)
                    if is_eicar or status == "DANGEROUS":
                        show_windows_toast("🔴 CyberThreat AI: Dangerous Threat in File Explorer", f"{file_name}\nThreat detected in file. Do not run.", "DANGEROUS", "http://localhost:5173/?tab=incidents&threat=1")
                        show_threat_alert_popup(
                            title="Threat Detected in File Explorer",
                            file_name=file_name,
                            status="DANGEROUS",
                            reasons=f_info.get("reasons", ["Malicious signature or high-risk file type detected in local filesystem."]),
                            launch_url="http://localhost:5173/?tab=incidents&threat=1"
                        )
                    elif status == "SUSPICIOUS":
                        show_windows_toast("🟠 CyberThreat AI: Suspicious File in File Explorer", f"{file_name}\nExecutable or high-risk file type detected.", "SUSPICIOUS", "http://localhost:5173/?tab=incidents&threat=1")
                        show_threat_alert_popup(
                            title="Suspicious File Detected",
                            file_name=file_name,
                            status="SUSPICIOUS",
                            reasons=f_info.get("reasons", ["High-risk executable or double extension detected."]),
                            launch_url="http://localhost:5173/?tab=incidents&threat=1"
                        )
                    else:
                        show_windows_toast("🟢 CyberThreat AI: Safe Download", f"{file_name}\nFile appears safe.", "SAFE")

                    event = {
                        "event_id": f"evt_file_{uuid.uuid4().hex[:10]}",
                        "device_id": self.device_id,
                        "user_id": self.user_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "FILE_DOWNLOAD",
                        "features": {
                            "file_name": file_name,
                            "display_name": file_name,
                            "description": f"File created: {file_name}",
                            "extension": f_info.get("extension"),
                            "sha256": f_info.get("sha256"),
                            "file_size": f_info.get("file_size_bytes"),
                            "is_eicar": is_eicar,
                            "raw_risk": f_info.get("risk_score"),
                            "status": status,
                            "activity_category": "Downloads"
                        },
                        "detection_source": "REAL_FILE_MONITOR"
                    }
                    self._emit_event(event)

                # 2. Check for newly spawned processes & application launches
                new_procs = self.process_monitor.check_new_processes()
                for p_info in new_procs:
                    disp_name = p_info.get("display_name") or p_info.get("name")
                    is_app = p_info.get("is_app", False)
                    status = p_info.get("status", "INFO")
                    is_ad = p_info.get("is_adware", False)
                    ev_type = p_info.get("event_type") or ("APPLICATION_START" if is_app else "PROCESS_START")
                    desc = p_info.get("description") or (f"{disp_name} opened" if is_app else f"Process started: {p_info.get('name')}")
                    
                    # Offline activities & app notifications (Safe or Not)
                    proc_key = (p_info.get("name") or disp_name).lower()
                    now_ts = time.time()
                    last_time = self._notified_procs.get(proc_key, 0)
                    should_notify = (now_ts - last_time > 45) or is_ad or status in ("DANGEROUS", "SUSPICIOUS")

                    if should_notify:
                        self._notified_procs[proc_key] = now_ts
                        if status == "DANGEROUS":
                            show_windows_toast("🔴 CyberThreat AI: Dangerous Process", f"{disp_name}\nThreat detected in executable. Action recommended.", "DANGEROUS", "http://localhost:5173/?tab=incidents&threat=1")
                            show_threat_alert_popup(
                                title="Dangerous Process Detected",
                                file_name=disp_name,
                                status="DANGEROUS",
                                reasons=p_info.get("reasons", ["Threat detected in process execution."]),
                                launch_url="http://localhost:5173/?tab=incidents&threat=1"
                            )
                        elif is_ad:
                            show_windows_toast("🟠 CyberThreat AI: Adware / Promotional Ad Detected", f"{disp_name}\nVerdict: Commercial scareware / promotional ad popup.\nSafe from malware, but aggressive upsell alert.", "SUSPICIOUS")
                        elif status == "SUSPICIOUS":
                            show_windows_toast("🟠 CyberThreat AI: Suspicious Activity", f"{disp_name}\nSuspicious offline activity detected.", "SUSPICIOUS")
                        # Do not pop up toasts for normal safe applications to avoid user notification fatigue

                    event = {
                        "event_id": f"evt_proc_{uuid.uuid4().hex[:10]}",
                        "device_id": self.device_id,
                        "user_id": self.user_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": ev_type,
                        "features": {
                            "process_name": p_info.get("name"),
                            "display_name": disp_name,
                            "description": desc,
                            "pid": p_info.get("pid"),
                            "exe_path": p_info.get("exe"),
                            "cmdline": p_info.get("cmdline"),
                            "raw_risk": p_info.get("risk_score"),
                            "status": status,
                            "is_adware": is_ad,
                            "activity_category": "Apps",
                            "start_time": p_info.get("start_time"),
                            "end_time": p_info.get("end_time"),
                            "duration_seconds": p_info.get("duration_seconds")
                        },
                        "detection_source": "REAL_PROCESS_MONITOR"
                    }
                    self._emit_event(event)

                # 2b. Periodically scan for active adware / scareware popups currently visible
                active_ads = self.process_monitor.find_active_adware_processes()
                for a_info in active_ads:
                    ad_name = a_info.get("display_name")
                    ad_key = (a_info.get("name") or ad_name).lower()
                    now_ts = time.time()
                    last_ad_time = self._notified_procs.get(ad_key, 0)
                    if now_ts - last_ad_time > 60:
                        self._notified_procs[ad_key] = now_ts
                        show_windows_toast(
                            "🟠 CyberThreat AI: Adware / Promotional Ad Detected",
                            f"{ad_name}\nVerdict: Commercial scareware / promotional ad popup.\nSafe from malware, but aggressive upsell alert.",
                            "SUSPICIOUS"
                        )
                        if self.pipeline_cb:
                            ad_event = {
                                "event_id": f"evt_ad_{uuid.uuid4().hex[:10]}",
                                "device_id": self.device_id,
                                "user_id": self.user_id,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "event_type": "APPLICATION_START",
                                "features": {
                                    "process_name": a_info.get("name"),
                                    "display_name": ad_name,
                                    "description": f"Adware / Promotional Popup: {ad_name}",
                                    "pid": a_info.get("pid"),
                                    "exe_path": a_info.get("exe"),
                                    "raw_risk": a_info.get("risk_score"),
                                    "status": "SUSPICIOUS",
                                    "is_adware": True,
                                    "activity_category": "Apps",
                                    "reasons": a_info.get("reasons", [])
                                },
                                "detection_source": "REAL_PROCESS_MONITOR"
                            }
                            self._emit_event(ad_event)

                # 3. Check for newly established network connections
                new_conns = self.network_monitor.check_new_connections()
                for c_info in new_conns:
                    p_name = c_info.get("process_name", "Process")
                    r_ip = c_info.get("remote_ip", "")
                    r_port = c_info.get("remote_port", 0)
                    status = c_info.get("threat_status", "INFO")

                    event = {
                        "event_id": f"evt_net_{uuid.uuid4().hex[:10]}",
                        "device_id": self.device_id,
                        "user_id": self.user_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": "NETWORK_CONNECTION",
                        "features": {
                            "process_name": p_name,
                            "display_name": f"{p_name} ({r_ip}:{r_port})" if p_name != "unknown" else f"{r_ip}:{r_port}",
                            "description": f"Network connection detected: {r_ip}:{r_port} ({p_name})",
                            "remote_ip": r_ip,
                            "remote_port": r_port,
                            "protocol": c_info.get("protocol", "TCP"),
                            "raw_risk": c_info.get("risk_score"),
                            "status": status,
                            "activity_category": "Network"
                        },
                        "detection_source": "REAL_NETWORK_MONITOR"
                    }
                    self._emit_event(event)

                # 4. Check active foreground window for both online website browsing and offline document/app activities
                # Focus strictly on the single foreground window the user is currently interacting with to prevent ping-pong spam
                import re
                fg_win = self._get_foreground_window()
                candidate_windows = [fg_win] if fg_win else self._get_active_desktop_windows()[:1]
                now_ts = time.time()
                for win in candidate_windows:
                    if not win:
                        continue
                    proc_name = (win.get("proc_name") or "").lower()
                    title = (win.get("title") or "").strip()
                    lower_title = title.lower()
                    if not title:
                        continue
                    
                    # Ignore CyberThreat AI's own desktop windows, web UI tabs, and local development noise
                    ignore_keywords = [
                        "intelligent real-time digital threat detection",
                        "cyberthreat ai",
                        "cyberthreat ai operations center",
                        "localhost",
                        "127.0.0.1",
                        ":5173",
                        ":8000",
                        "wants to",
                        "permission",
                        "new tab",
                        "about:blank",
                        "task switching",
                        "program manager",
                        "windows input experience",
                        "settings",
                        "start"
                    ]
                    if any(k in proc_name for k in ["electron", "cyberthreat"]) or any(k in lower_title for k in ignore_keywords):
                        continue

                    # Detect browser windows (Chrome, Edge, Brave, Firefox, Opera, Vivaldi)
                    is_browser = any(b in proc_name for b in ["chrome", "msedge", "brave", "firefox", "opera", "vivaldi"]) or \
                                 any(b_tag in lower_title for b_tag in [" - google chrome", " - microsoft edge", " - brave", " - firefox", " - opera"])
                    
                    if is_browser:
                        # Extract clean page title
                        clean_page_title = re.sub(r'\s*-\s*(Google Chrome|Microsoft Edge|Brave|Firefox|Opera|Vivaldi)$', '', title, flags=re.I).strip()
                        if not clean_page_title or clean_page_title.lower() in ("new tab", "about:blank"):
                            continue

                        last_logged = self._browser_title_last_logged.get(clean_page_title, 0.0)
                        is_different = (clean_page_title != self._last_active_browser_title)

                        # Record when user switches to a distinct page (10s debounce) or on a 300s heartbeat
                        if (is_different and (now_ts - last_logged) >= 10) or (not is_different and (now_ts - last_logged) >= 300):
                            self._last_active_browser_title = clean_page_title
                            self._browser_title_last_logged[clean_page_title] = now_ts

                            # Extract or infer domain accurately
                            detected_domain = None
                            if any(gm in lower_title for gm in ["gmail", "inbox", "mail.google.com", "@gmail.com"]):
                                detected_domain = "mail.google.com"
                            elif any(yt in lower_title for yt in ["youtube", "lyrical", "video", "thandel", "music", "song"]):
                                detected_domain = "youtube.com"
                            elif "github" in lower_title:
                                detected_domain = "github.com"
                            elif "google" in lower_title:
                                detected_domain = "google.com"
                            else:
                                for d in ["reddit.com", "netflix.com", "amazon.com", "wikipedia.org", "stackoverflow.com", "chatgpt.com", "openai.com", "microsoft.com"]:
                                    if d in lower_title or d.replace(".com", "") in lower_title:
                                        detected_domain = d
                                        break
                            if not detected_domain:
                                domain_match = re.search(r'\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b', clean_page_title)
                                if domain_match:
                                    detected_domain = domain_match.group(1).lower()
                            if not detected_domain and clean_page_title.lower() not in ("new tab", "about:blank"):
                                detected_domain = "web-browsing.local"
                            
                            if detected_domain:
                                self.record_browser_navigation(f"https://{detected_domain}", title=clean_page_title)
                        elif is_different:
                            self._last_active_browser_title = clean_page_title
                    else:
                        # Detect ANY offline user application or document (Notepad, Word, Excel, File Explorer, Command Prompt, PowerShell, VS Code, Paint, etc.)
                        system_window_titles = {"program manager", "windows input experience", "settings", "start", "task switching"}
                        if lower_title not in system_window_titles and not any(k in proc_name for k in ["electron", "cyberthreat"]):
                            app_key = f"{proc_name}::{title}"
                            last_logged_doc = self._doc_title_last_logged.get(app_key, 0.0)

                            # Record with responsive 30s debounce per document/app window to prevent spamming
                            if (now_ts - last_logged_doc) >= 30:
                                self._doc_title_last_logged[app_key] = now_ts
                                friendly_names = {
                                    "explorer.exe": "File Explorer",
                                    "notepad.exe": "Notepad",
                                    "notepad++.exe": "Notepad++",
                                    "cmd.exe": "Command Prompt",
                                    "powershell.exe": "PowerShell",
                                    "code.exe": "VS Code",
                                    "winword.exe": "Microsoft Word",
                                    "excel.exe": "Microsoft Excel",
                                    "powerpnt.exe": "Microsoft PowerPoint",
                                    "mspaint.exe": "Paint",
                                    "calc.exe": "Calculator",
                                    "spotify.exe": "Spotify",
                                    "vlc.exe": "VLC Media Player",
                                    "taskmgr.exe": "Task Manager"
                                }
                                app_display = friendly_names.get(proc_name, proc_name.replace(".exe", "").capitalize())

                                doc_event = {
                                    "event_id": f"evt_off_{uuid.uuid4().hex[:10]}",
                                    "device_id": self.device_id,
                                    "user_id": self.user_id,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "event_type": "APPLICATION_START",
                                    "features": {
                                        "process_name": win.get("proc_name"),
                                        "display_name": f"{app_display}: {title}" if title else app_display,
                                        "description": f"Active in {app_display} ({title})" if title else f"Active application: {app_display}",
                                        "pid": win.get("pid"),
                                        "status": "SAFE",
                                        "raw_risk": 0.0,
                                        "activity_category": "Apps",
                                        "activity_domain": "OFFLINE",
                                        "connectivity_state": "ONLINE" if self._running else "OFFLINE"
                                    },
                                    "detection_source": "REAL_WINDOW_MONITOR"
                                }
                                self._emit_event(doc_event)

                # Periodic heartbeat in local DB to maintain ONLINE status
                if self.db and hasattr(self.db, "update_device_status"):
                    try:
                        self.db.update_device_status(self.device_id, "ONLINE")
                    except Exception:
                        pass

            except Exception:
                pass

            time.sleep(self._scan_interval_sec)

    def record_browser_navigation(
        self,
        raw_url: str,
        title: str = "",
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        is_test_event: bool = False,
        browser_event_type: str = "WEBSITE_OPENED",
        email_threat_indicators: Optional[Dict[str, Any]] = None,
        verdict_override: Optional[str] = None,
        reasons_override: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Processes a genuine browser navigation or Gmail email inspection event sent from Chrome Extension.
        Displays real-time Windows toast notifications and persists to SQLite.
        """
        import urllib.parse
        # Zero-collection privacy enforcement: sanitize URL to strip tokens, passwords, cookies, and secrets
        try:
            parsed = urllib.parse.urlparse(raw_url)
            if parsed.query:
                params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                sanitized_params = []
                sensitive_keys = {"password", "pwd", "token", "auth", "secret", "session", "key", "access_token", "apikey", "api_key", "cookie", "code"}
                for k, v in params:
                    if k.lower() in sensitive_keys:
                        sanitized_params.append((k, "[REDACTED]"))
                    else:
                        sanitized_params.append((k, v))
                clean_query = urllib.parse.urlencode(sanitized_params)
                sanitized_url = urllib.parse.urlunparse(parsed._replace(query=clean_query))
            else:
                sanitized_url = raw_url
        except Exception:
            sanitized_url = raw_url

        eval_res = self.domain_evaluator.evaluate_url(sanitized_url)
        domain = eval_res.get("domain", sanitized_url)
        status = verdict_override or eval_res.get("status", "SAFE")
        if verdict_override in ("DANGER", "DANGEROUS"):
            eval_res["risk_score"] = max(eval_res.get("risk_score", 0.0), 90.0)
            eval_res["status"] = "DANGER"
        elif verdict_override == "SUSPICIOUS":
            eval_res["risk_score"] = max(eval_res.get("risk_score", 0.0), 65.0)
            eval_res["status"] = "SUSPICIOUS"
        reasons = reasons_override if reasons_override is not None else eval_res.get("reasons", [])
        target_device = device_id if device_id and device_id not in ("DEV-LOCAL", "DEV-HOST") else self.device_id
        target_user = user_id if user_id and user_id not in ("current_user", "") else self.user_id
        is_test = is_test_event or eval_res.get("is_test_intent", False)

        is_gmail = browser_event_type == "GMAIL_INSPECTION" or "mail.google.com" in domain

        clean_title = (title or "").strip()
        if clean_title.endswith("- YouTube"):
            clean_title = clean_title[:-9].strip()
        elif clean_title.endswith("YouTube"):
            clean_title = clean_title[:-7].strip()

        is_youtube = any(yt in domain.lower() for yt in ["youtube.com", "youtu.be"]) or ("youtube.com" in raw_url.lower())
        
        if is_gmail and email_threat_indicators:
            if isinstance(email_threat_indicators, dict):
                sender = email_threat_indicators.get("sender", "Unknown Sender")
                subj = email_threat_indicators.get("subject_snippet", "")
            elif isinstance(email_threat_indicators, list):
                sender = email_threat_indicators[0] if email_threat_indicators else "Unknown Sender"
                subj = ""
            else:
                sender = str(email_threat_indicators)
                subj = ""
            display_name = f"Gmail Inspection: {sender}"
            description = f"Gmail email inspected from {sender} — Verdict: {status}"
            if subj:
                description += f' ("{subj}")'
        elif is_youtube:
            if clean_title:
                description = f"Watched YouTube video: \"{clean_title}\""
                display_name = f"YouTube: {clean_title}"
            elif "/watch" in raw_url:
                import urllib.parse
                try:
                    parsed = urllib.parse.urlparse(raw_url)
                    params = urllib.parse.parse_qs(parsed.query)
                    v_id = params.get("v", [""])[0]
                    description = f"Watched YouTube video (ID: {v_id})" if v_id else "Watched YouTube video"
                except Exception:
                    description = "Watched YouTube video"
                display_name = "YouTube Video"
            elif "/shorts" in raw_url:
                description = "Watched YouTube Shorts video"
                display_name = "YouTube Shorts"
            else:
                description = f"Opened YouTube ({domain})"
                display_name = "YouTube"
        else:
            if clean_title:
                description = f"Visited \"{clean_title}\" on {domain}"
                display_name = clean_title
            else:
                description = f"Website opened: {domain}"
                display_name = domain

        # Native Windows Toast Notification strictly reserved for DANGEROUS or SUSPICIOUS events
        if status in ("DANGEROUS", "SUSPICIOUS"):
            now_ts = time.time()
            s_name = "Sender"
            if is_gmail and email_threat_indicators:
                if isinstance(email_threat_indicators, dict):
                    s_name = email_threat_indicators.get("sender", "Sender")
                elif isinstance(email_threat_indicators, list) and email_threat_indicators:
                    s_name = str(email_threat_indicators[0])
            notif_key = f"{domain}:{s_name}"
            last_time = self._notified_domains.get(notif_key, 0)
            if now_ts - last_time > 30:
                self._notified_domains[notif_key] = now_ts
                if is_gmail:
                    if status == "DANGEROUS":
                        show_windows_toast("🔴 CyberThreat AI", f"Phishing Email Detected\nFrom: {s_name}\nDo not click links or attachments.", "DANGEROUS")
                    elif status == "SUSPICIOUS":
                        show_windows_toast("🟠 CyberThreat AI", f"Suspicious Email Alert\nFrom: {s_name}\nVerify sender before interacting.", "SUSPICIOUS")
                else:
                    if status == "DANGEROUS":
                        show_windows_toast("🔴 CyberThreat AI", f"Dangerous website detected\n{domain}\nDo not continue.", "DANGEROUS")
                    elif status == "SUSPICIOUS":
                        show_windows_toast("🟠 CyberThreat AI", f"Suspicious website detected\n{domain}\nReview before continuing.", "SUSPICIOUS")

        event = {
            "event_id": f"evt_web_{uuid.uuid4().hex[:10]}",
            "device_id": target_device,
            "user_id": target_user,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": browser_event_type,
            "features": {
                "url": sanitized_url,
                "domain": domain,
                "title": title or "",
                "page_title": title or "",
                "clean_title": clean_title,
                "display_name": display_name,
                "description": description,
                "status": status,
                "raw_risk": eval_res.get("risk_score"),
                "category": eval_res.get("category"),
                "reasons": reasons,
                "activity_category": "Browser",
                "is_test_event": is_test,
                "is_youtube": is_youtube,
                "is_gmail": is_gmail,
                "email_threat_indicators": email_threat_indicators or {}
            },
            "detection_source": "CHROME_EXTENSION_API"
        }
        processed = self._emit_event(event)
        
        ret_event = processed or event
        return {
            "status": status,
            "domain": domain,
            "risk_score": ret_event.get("risk_score", eval_res.get("risk_score")),
            "reasons": reasons,
            "evaluation": eval_res,
            "event": ret_event
        }

