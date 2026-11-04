"""
Independent Monitoring Agent / Collector for Multi-Device Telemetry.

Runs on secondary/friend devices (Device B), collecting independent host telemetry
and reporting to the central CyberThreat AI backend:
- Preserves strict device identity (unique device_id per physical host)
- Emits real process, file, network, and browser telemetry
- Sends Windows notifications ONLY on THIS local host
- Sends heartbeat to update last_seen on central backend
"""

import sys
import time
import uuid
import platform
import argparse
import requests
from datetime import datetime, timezone
from pathlib import Path

from backend.monitoring.process_monitor import ProcessMonitor
from backend.monitoring.file_monitor import FileMonitor
from backend.monitoring.network_monitor import NetworkMonitor
from backend.monitoring.domain_evaluator import DomainEvaluator
from backend.monitoring.windows_notifier import show_windows_toast

class RemoteDeviceAgent:
    """Agent running on a separate host (e.g. Friend's Laptop) reporting to central backend."""

    def __init__(self, server_url: str, device_id: str, device_name: str = "Friend's Laptop", user_id: str = "current_user", auth_token: Optional[str] = None):
        self.server_url = server_url.rstrip("/")
        self.device_id = device_id
        self.device_name = device_name
        self.user_id = user_id
        self.auth_token = auth_token
        self.os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
        
        self.process_monitor = ProcessMonitor()
        self.file_monitor = FileMonitor()
        self.network_monitor = NetworkMonitor()
        self.domain_evaluator = DomainEvaluator()
        self._running = False

    def _get_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def register(self) -> bool:
        """Registers this device on the central backend."""
        try:
            url = f"{self.server_url}/api/devices/register"
            payload = {
                "device_id": self.device_id,
                "user_id": self.user_id,
                "device_name": self.device_name,
                "os_info": self.os_info
            }
            res = requests.post(url, json=payload, headers=self._get_headers(), timeout=5)
            if res.ok:
                print(f"[+] Device {self.device_id} ('{self.device_name}') successfully registered on {self.server_url}")
                return True
            else:
                print(f"[-] Registration failed: {res.status_code} {res.text}")
                return False
        except Exception as e:
            print(f"[-] Cannot reach backend server at {self.server_url}: {e}")
            return False

    def send_event(self, event: dict) -> bool:
        """Sends a telemetry event to central backend with this device's device_id."""
        event["device_id"] = self.device_id
        event["user_id"] = event.get("user_id") or self.user_id
        if not event.get("event_id"):
            event["event_id"] = f"evt_rem_{uuid.uuid4().hex[:10]}"
        if not event.get("timestamp"):
            event["timestamp"] = datetime.now(timezone.utc).isoformat()
        try:
            url = f"{self.server_url}/api/telemetry/event"
            res = requests.post(url, json=event, headers=self._get_headers(), timeout=5)
            return res.ok
        except Exception:
            return False

    def record_browser_visit(self, url: str) -> dict:
        """Records browser visit on this friend device and displays local notification."""
        eval_res = self.domain_evaluator.evaluate_url(url)
        domain = eval_res.get("domain", url)
        status = eval_res.get("status", "SAFE")

        # Notify locally on THIS friend's machine ONLY (Req 20)
        if status == "DANGEROUS":
            show_windows_toast("🔴 CyberThreat AI", f"Dangerous website detected\n{domain}\nDo not continue.", "DANGEROUS")
        elif status == "SUSPICIOUS":
            show_windows_toast("🟠 CyberThreat AI", f"Suspicious website detected\n{domain}\nReview before continuing.", "SUSPICIOUS")
        else:
            show_windows_toast("🟢 CyberThreat AI", f"{domain}\nWebsite appears safe.", "SAFE")

        event = {
            "event_id": f"evt_web_{uuid.uuid4().hex[:10]}",
            "device_id": self.device_id,
            "user_id": "current_user",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "WEBSITE_OPENED",
            "features": {
                "url": url,
                "domain": domain,
                "display_name": domain,
                "description": f"Website opened: {domain}",
                "status": status,
                "raw_risk": eval_res.get("risk_score"),
                "category": eval_res.get("category"),
                "reasons": eval_res.get("reasons", []),
                "activity_category": "Browser"
            },
            "detection_source": "FRIEND_AGENT_BROWSER"
        }
        self.send_event(event)
        return eval_res

    def run(self):
        """Main agent collection loop."""
        self._running = True
        print(f"[*] Starting CyberThreat AI Agent on {self.device_id}...")
        self.register()

        last_heartbeat = 0
        while self._running:
            try:
                now = time.time()
                # Heartbeat every 30s to keep last_seen fresh
                if now - last_heartbeat > 30:
                    self.register()
                    last_heartbeat = now

                # 1. Process checks
                procs = self.process_monitor.check_new_processes()
                for p in procs:
                    disp_name = p.get("display_name") or p.get("name")
                    is_app = p.get("is_app", False)
                    status = p.get("status", "INFO")
                    ev_type = p.get("event_type") or ("APPLICATION_START" if is_app else "PROCESS_START")
                    desc = p.get("description") or (f"{disp_name} opened" if is_app else f"Process started: {p.get('name')}")
                    
                    event = {
                        "event_id": f"evt_proc_{uuid.uuid4().hex[:10]}",
                        "device_id": self.device_id,
                        "user_id": self.user_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "event_type": ev_type,
                        "features": {
                            "process_name": p.get("name"),
                            "display_name": disp_name,
                            "description": desc,
                            "pid": p.get("pid"),
                            "exe_path": p.get("exe"),
                            "cmdline": p.get("cmdline"),
                            "raw_risk": p.get("risk_score"),
                            "status": status,
                            "activity_category": "Apps"
                        },
                        "detection_source": "FRIEND_AGENT_PROCESS"
                    }
                    self.send_event(event)

                # 2. File download checks
                files = self.file_monitor.check_new_downloads()
                for f in files:
                    file_name = f.get("file_name", "downloaded_file")
                    status = f.get("status", "SAFE")
                    is_eicar = f.get("is_eicar_test", False)

                    # Notify locally on THIS friend's device
                    if is_eicar or status == "DANGEROUS":
                        show_windows_toast("🔴 CyberThreat AI", f"Dangerous Download\n{file_name}", "DANGEROUS")
                    elif status == "SUSPICIOUS":
                        show_windows_toast("🟠 CyberThreat AI", f"Suspicious Download\n{file_name}", "SUSPICIOUS")
                    else:
                        show_windows_toast("🟢 CyberThreat AI", f"Safe Download\n{file_name}", "SAFE")

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
                            "extension": f.get("extension"),
                            "sha256": f.get("sha256"),
                            "file_size": f.get("file_size_bytes"),
                            "is_eicar": is_eicar,
                            "raw_risk": f.get("risk_score"),
                            "status": status,
                            "activity_category": "Downloads"
                        },
                        "detection_source": "FRIEND_AGENT_FILE"
                    }
                    self.send_event(event)

            except Exception as e:
                pass

            time.sleep(3.0)

def main():
    parser = argparse.ArgumentParser(description="CyberThreat AI Monitoring Agent for Separate Devices")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Central CyberThreat AI server URL")
    parser.add_argument("--device-id", required=True, help="Unique device ID for this machine (e.g. DEVICE_B_FRIEND)")
    parser.add_argument("--name", default="Friend's Laptop", help="Human-readable device name")
    parser.add_argument("--user-id", default="current_user", help="Authenticated user ID to bind telemetry")
    parser.add_argument("--token", default=None, help="Bearer authorization token")
    parser.add_argument("--test-url", help="Instantly report a browser test URL and exit")
    args = parser.parse_args()

    agent = RemoteDeviceAgent(server_url=args.server, device_id=args.device_id, device_name=args.name, user_id=args.user_id, auth_token=args.token)
    if args.test_url:
        agent.register()
        res = agent.record_browser_visit(args.test_url)
        print(f"[*] Reported {args.test_url} from {args.device_id}: {res.get('status')}")
        return

    agent.run()

if __name__ == "__main__":
    main()
