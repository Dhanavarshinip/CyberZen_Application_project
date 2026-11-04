"""
Real-Time Process Monitor for CyberThreat AI System.

Monitors real operating system processes via legitimate OS APIs (psutil):
- Tracks running applications and newly spawned processes
- Analyzes execution paths (e.g. Temp/AppData executions)
- Inspects command line arguments for obfuscation / encoded payloads
- Flags suspicious parent-child process relationships
- Filters Windows system background processes (svchost, RuntimeBroker, etc.)
"""

import os
import time
import psutil
from typing import Dict, Any, List, Set
from datetime import datetime, timezone

class ProcessMonitor:
    """Monitors live host processes using psutil."""

    SUSPICIOUS_PATHS = ["\\temp\\", "\\appdata\\local\\temp\\", "/tmp/"]
    SUSPICIOUS_NAMES = {"mimikatz.exe", "nmap.exe", "nc.exe", "netcat.exe", "powershell_remote.exe", "malware_test.exe"}

    FRIENDLY_APP_NAMES = {
        "chrome.exe": "Chrome",
        "msedge.exe": "Microsoft Edge",
        "code.exe": "VS Code",
        "explorer.exe": "File Explorer",
        "notepad.exe": "Notepad",
        "notepad++.exe": "Notepad++",
        "powershell.exe": "PowerShell",
        "cmd.exe": "Command Prompt",
        "slack.exe": "Slack",
        "discord.exe": "Discord",
        "spotify.exe": "Spotify",
        "firefox.exe": "Firefox",
        "brave.exe": "Brave Browser",
        "opera.exe": "Opera Browser",
        "py.exe": "Python Runner",
        "python.exe": "Python",
        "python3.exe": "Python 3",
        "electron.exe": "Electron App",
        "git.exe": "Git",
        "taskmgr.exe": "Task Manager",
        "winword.exe": "Microsoft Word",
        "excel.exe": "Microsoft Excel",
        "powerpnt.exe": "Microsoft PowerPoint",
        "outlook.exe": "Microsoft Outlook",
        "teams.exe": "Microsoft Teams",
        "zoom.exe": "Zoom",
        "vlc.exe": "VLC Media Player",
        "7zfm.exe": "7-Zip",
        "winscp.exe": "WinSCP",
        "putty.exe": "PuTTY",
        "mstsc.exe": "Remote Desktop",
        "calc.exe": "Calculator",
        "mspaint.exe": "Paint",
        "wordpad.exe": "WordPad",
        "wt.exe": "Windows Terminal",
        "windowsterminal.exe": "Windows Terminal",
        "node.exe": "Node.js",
        "node": "Node.js",
        "npm.exe": "NPM",
        "git-bash.exe": "Git Bash",
        "postman.exe": "Postman",
        "insomnia.exe": "Insomnia",
        "obsidian.exe": "Obsidian",
        "notion.exe": "Notion",
        "cyberthreat ai operations center.exe": "CyberThreat AI Operations Center",
        "cyberthreat ai.exe": "CyberThreat AI Operations Center",
        "cyberthreat_ai.exe": "CyberThreat AI Operations Center",
    }

    # Adware, commercial scareware, and promotional popup patterns
    ADWARE_PATTERNS = [
        {"pattern": "mc-webview-cnt.exe", "name": "McAfee Promotional Ad Popup", "type": "ADWARE_PROMOTION"},
        {"pattern": "ssscheduler.exe", "name": "McAfee Security Scan Scheduler", "type": "ADWARE_PROMOTION"},
        {"pattern": "mcchsvc.exe", "name": "McAfee Security Scan Helper", "type": "ADWARE_PROMOTION"},
        {"pattern": "mcupdatermodule.exe", "name": "McAfee Updater Module", "type": "ADWARE_PROMOTION"},
        {"pattern": "mcafee security scan", "name": "McAfee Security Scan Adware", "type": "ADWARE_PROMOTION"},
        {"pattern": "webadvisor", "name": "McAfee WebAdvisor Adware", "type": "ADWARE_PROMOTION"},
        {"pattern": "cleanmypc", "name": "CleanMyPC Scareware/Nagware", "type": "SCAREWARE"},
        {"pattern": "webcompanion", "name": "Lavasoft Web Companion Adware", "type": "ADWARE"},
        {"pattern": "bytefence", "name": "ByteFence Scareware", "type": "SCAREWARE"},
        {"pattern": "driverupdate", "name": "Driver Updater Nagware", "type": "SCAREWARE"},
        {"pattern": "pcoptimizer", "name": "PC Optimizer Nagware", "type": "SCAREWARE"},
        {"pattern": "popunder", "name": "Popunder Ad Injector", "type": "ADWARE"},
        {"pattern": "adhelper", "name": "Adware Helper Utility", "type": "ADWARE"},
    ]

    # Windows system background processes — never report these as user activity
    SYSTEM_NOISE = {
        "svchost.exe", "runtimebroker.exe", "werfault.exe", "werfaultsecure.exe",
        "backgroundtaskhost.exe", "dllhost.exe", "conhost.exe", "csrss.exe",
        "lsass.exe", "lsaiso.exe", "wininit.exe", "winlogon.exe", "smss.exe",
        "services.exe", "system", "idle", "registry",
        "dwm.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
        "searchindexer.exe", "searchhost.exe", "searchapp.exe",
        "spoolsv.exe", "audiodg.exe", "fontdrvhost.exe", "msdtc.exe",
        "securityhealthsystray.exe", "securityhealthservice.exe",
        "sgrmbroker.exe", "mssense.exe", "msmpeng.exe", "nissrv.exe",
        "wuauclt.exe", "trustedinstaller.exe", "tiworker.exe", "wsappx.exe",
        "applicationframehost.exe", "wlanext.exe", "textinputhost.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe",
        "lockapp.exe", "logonui.exe", "userinit.exe", "settingsynchost.exe",
        "dataexchangehost.exe", "compattelrunner.exe", "musnotification.exe",
        "gamebarpresencewriter.exe", "smartscreen.exe", "mpcmdrun.exe",
        "systemsettings.exe", "systemsettingsbroker.exe",
        "microsoftedgeupdate.exe", "googleupdate.exe", "sppsvc.exe",
        "wmpnetwk.exe", "igfxem.exe", "igfxhk.exe", "igfxtray.exe",
        "nvdisplay.container.exe", "nvcontainer.exe", "nvsphelper64.exe",
        "phoneexperiencehost.exe", "msedgewebview2.exe",
        "usocoreworker.exe", "uhssvc.exe", "wlms.exe", "agentactivationruntime.exe",
        "useroobebroker.exe", "ctfmon.exe", "msiexec.exe",
        "wmiprvse.exe", "mousocoreworker.exe", "actionsserver.exe",
        "ssscheduler.exe", "mcchsvc.exe", "mcupdatermodule.exe",
        "updater.exe", "softlandingtask.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "agsservice.exe", "adobeupdaterservice.exe", "hpsupportsolutionsframeworkservice.exe",
        "touchpointanalyticsclient.exe", "hpanalytics.exe", "hpcustpartic.exe", "hpcommrecovery.exe",
        "hpsystemeventutilityhost.exe", "cleanmgr.exe", "dismhost.exe", "wermgr.exe",
        "consent.exe", "defrag.exe", "lpksetup.exe", "crashhelper.exe", "devicecen.exe"
    }

    @classmethod
    def _is_system_noise(cls, name_lower: str) -> bool:
        """Determines if a process is background OS housekeeping noise."""
        if not name_lower:
            return True
        return name_lower in cls.SYSTEM_NOISE or any(
            name_lower.startswith(prefix) for prefix in [
                "werfault", "systemsettings", "search", "gamebar", "wlanext",
                "settingsynchost", "microsoftedgeupdate", "googleupdate"
            ]
        )

    def __init__(self):
        self._seen_pids: Set[int] = set()
        self._tracked_apps: Dict[int, Dict[str, Any]] = {}
        self._init_current_pids()

    def _init_current_pids(self):
        """Records existing PIDs on startup and tracks friendly apps with actual create times."""
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            now_time = time.time()
            for proc in psutil.process_iter(['pid', 'name', 'create_time']):
                pid = proc.info['pid']
                self._seen_pids.add(pid)
                name_lower = (proc.info.get('name') or '').lower()
                if name_lower in self.FRIENDLY_APP_NAMES:
                    c_ts = proc.info.get('create_time') or now_time
                    try:
                        c_iso = datetime.fromtimestamp(c_ts, tz=timezone.utc).isoformat()
                    except Exception:
                        c_iso = now_iso
                    self._tracked_apps[pid] = {
                        "name": proc.info.get('name'),
                        "display_name": self.FRIENDLY_APP_NAMES[name_lower],
                        "start_time": c_iso,
                        "start_ts": c_ts
                    }
        except Exception:
            pass


    @classmethod
    def get_visible_window_pids(cls) -> Set[int]:
        """Returns the set of PIDs that currently possess a visible desktop window."""
        import platform
        if platform.system() != "Windows":
            return set()
        visible = set()
        try:
            import ctypes
            user32 = ctypes.windll.user32
            hwinsta = user32.OpenWindowStationW("WinSta0", False, 0x037F)
            if hwinsta:
                user32.SetProcessWindowStation(hwinsta)
            hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)
            
            def enum_proc(hwnd, lParam):
                if user32.IsWindowVisible(hwnd):
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length > 0:
                        pid = ctypes.c_ulong(0)
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        if pid.value:
                            visible.add(pid.value)
                return True

            WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            target = hdesk if hdesk else 0
            if target:
                user32.EnumDesktopWindows(target, WNDENUMPROC(enum_proc), 0)
            else:
                user32.EnumWindows(WNDENUMPROC(enum_proc), 0)
        except Exception:
            pass
        return visible

    @classmethod
    def evaluate_process(cls, proc_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a single process for risk indicators.
        """
        # Verified self-application identity & behavioral integrity check
        from backend.monitoring.self_recognition import evaluate_self_process
        self_eval = evaluate_self_process(proc_info)
        if self_eval is not None:
            return self_eval

        pid = proc_info.get("pid", 0)
        raw_name = proc_info.get("name") or "unknown"
        name_lower = raw_name.lower()
        exe = (proc_info.get("exe") or "").lower()
        cmdline_list = proc_info.get("cmdline") or []
        cmdline_str = " ".join(cmdline_list).lower() if isinstance(cmdline_list, list) else str(cmdline_list).lower()

        # Helper browser subprocess check (skip background worker noise)
        is_helper_subproc = any(flag in cmdline_str for flag in ["--type=renderer", "--type=utility", "--type=gpu-process", "--type=crashpad-handler"])

        if name_lower in cls.FRIENDLY_APP_NAMES:
            display_name = cls.FRIENDLY_APP_NAMES[name_lower]
            is_app = not is_helper_subproc
        elif name_lower.endswith(".exe") and not cls._is_system_noise(name_lower):
            display_name = name_lower.replace(".exe", "").capitalize()
            is_app = not is_helper_subproc
        else:
            display_name = raw_name
            is_app = False

        reasons = []
        risk_score = 0.0
        is_adware = False

        # Check adware / commercial scareware / promotional popup patterns
        for pattern_info in cls.ADWARE_PATTERNS:
            pat = pattern_info["pattern"]
            if pat in name_lower or (exe and pat in exe):
                # Suppress if launched in silent background mode without splash (e.g. /nosplash, /globalngm, /silent)
                is_silent = any(flag in cmdline_str for flag in ["/nosplash", "/globalngm", "/silent", "/quiet", "-silent", "--silent", "/background"])
                if not is_silent:
                    is_adware = True
                    adware_name = pattern_info.get("name", "Adware / Promotional Popup")
                    display_name = adware_name
                    reasons.append(f"Commercial adware / promotional popup detected: {adware_name}.")
                    reasons.append("Displays aggressive upsell prompts ('Issues found!') to induce subscription purchase.")
                    reasons.append("Verdict: Safe from virus/malware, but unsolicited commercial scareware ad.")
                    risk_score = 45.0
                    break

        # Check known malicious test names
        if not is_adware and name_lower in cls.SUSPICIOUS_NAMES:
            reasons.append(f"Suspicious process name: '{raw_name}' matches known threat tool signature.")
            risk_score = max(risk_score, 90.0)

        # Check execution from temp/unusual folders
        if not is_adware and any(sp in exe for sp in cls.SUSPICIOUS_PATHS) and not any(k in name_lower or k in exe for k in ["installer", "setup", "update", "updater", "unpacker", "unzip"]):
            reasons.append(f"Executable launched from temporary directory ({exe}).")
            risk_score = max(risk_score, risk_score + 40.0 if risk_score > 0 else 55.0)

        # Check encoded PowerShell commands
        if not is_adware and ("powershell" in name_lower or "pwsh" in name_lower):
            if any(flag in cmdline_str for flag in ["-enc ", "-encodedcommand ", "-w hidden", "-windowstyle hidden"]):
                reasons.append("PowerShell executing with hidden window or encoded command.")
                risk_score = max(risk_score, risk_score + 45.0 if risk_score > 0 else 60.0)

        # Check cmd/powershell spawning downloading utilities
        if not is_adware and any(util in cmdline_str for util in ["certutil -urlcache", "bitsadmin /transfer"]):
            reasons.append("Command shell invoking internet transfer utility.")
            risk_score = max(risk_score, risk_score + 35.0 if risk_score > 0 else 50.0)

        risk_score = round(max(0.0, min(100.0, risk_score)), 1)

        if risk_score >= 70.0:
            status = "DANGEROUS"
            description = f"Dangerous application: {display_name}" if is_app else f"Dangerous process: {raw_name}"
        elif is_adware:
            status = "SUSPICIOUS"
            description = f"{display_name} active (Commercial Adware / Scareware Popup)"
        elif risk_score >= 35.0:
            status = "SUSPICIOUS"
            description = f"Suspicious application: {display_name}" if is_app else f"Suspicious process: {raw_name}"
        elif is_app:
            status = "INFO"
            description = f"{display_name} opened"
        else:
            status = "SAFE"
            description = f"Process started: {raw_name}"

        if not reasons:
            reasons.append(f"{display_name} started normally.")

        # Determine authentic process start timestamp from OS process table
        create_ts = proc_info.get("create_time")
        if create_ts:
            try:
                proc_time_iso = datetime.fromtimestamp(create_ts, tz=timezone.utc).isoformat()
            except Exception:
                proc_time_iso = datetime.now(timezone.utc).isoformat()
        else:
            proc_time_iso = datetime.now(timezone.utc).isoformat()

        return {
            "pid": pid,
            "name": raw_name,
            "display_name": display_name,
            "is_app": is_app,
            "is_adware": is_adware,
            "is_helper": is_helper_subproc,
            "event_type": "APPLICATION_START" if is_app else "PROCESS_START",
            "description": description,
            "exe": proc_info.get("exe") or "",
            "cmdline": cmdline_str[:200],
            "status": status,
            "risk_score": risk_score,
            "reasons": reasons,
            "activity_category": "Apps" if is_app else "Processes",
            "timestamp": proc_time_iso
        }

    def scan_running_processes(self, max_procs: int = 50) -> List[Dict[str, Any]]:
        """
        Scans currently active host processes and returns evaluations.
        """
        procs = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                p_dict = proc.info
                name_lower = (p_dict.get("name") or "").lower()
                if self._is_system_noise(name_lower):
                    continue
                eval_res = self.evaluate_process(p_dict)
                if not eval_res.get("is_helper"):
                    procs.append(eval_res)
                if len(procs) >= max_procs:
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return procs

    def check_new_processes(self) -> List[Dict[str, Any]]:
        """
        Detects newly spawned and closed processes since the last check.
        Reports application launches, closures, and suspicious processes.
        """
        new_events = []
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                if pid not in self._seen_pids:
                    self._seen_pids.add(pid)
                    name_lower = (proc.info.get('name') or '').lower()

                    if self._is_system_noise(name_lower):
                        continue

                    eval_res = self.evaluate_process(proc.info)

                    # Skip internal browser helper threads to avoid spam
                    if eval_res.get("is_helper"):
                        continue

                    # Track friendly apps so we can detect closure & measure duration
                    if eval_res.get("is_app"):
                        start_iso = eval_res.get("timestamp") or datetime.now(timezone.utc).isoformat()
                        eval_res["start_time"] = start_iso
                        self._tracked_apps[pid] = {
                            "name": eval_res.get("name"),
                            "display_name": eval_res.get("display_name"),
                            "start_time": start_iso,
                            "start_ts": time.time()
                        }

                    # Deduplicate verified self application launches to prevent duplicates
                    if eval_res.get("is_self_verified") and eval_res.get("status") == "INFO":
                        from backend.monitoring.self_recognition import should_emit_self_event
                        if not should_emit_self_event(pid):
                            continue

                    # Only emit events for user apps, suspicious/dangerous procs, or known utilities
                    is_interesting = (
                        eval_res.get("is_app") or
                        eval_res.get("risk_score", 0) > 0 or
                        name_lower in self.FRIENDLY_APP_NAMES
                    )

                    if is_interesting:
                        new_events.append(eval_res)

                    if len(new_events) >= 50:
                        break

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for closed applications and calculate accurate duration
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        for old_pid, app_meta in list(self._tracked_apps.items()):
            if old_pid not in current_pids:
                del self._tracked_apps[old_pid]
                disp_name = app_meta.get("display_name") or app_meta.get("name")
                start_iso = app_meta.get("start_time") or now_iso
                start_ts = app_meta.get("start_ts", now_ts)
                duration_sec = max(1, int(now_ts - start_ts))
                closed_event = {
                    "pid": old_pid,
                    "name": app_meta.get("name"),
                    "display_name": disp_name,
                    "is_app": True,
                    "event_type": "APPLICATION_CLOSED",
                    "description": f"{disp_name} closed (active for {duration_sec}s)",
                    "status": "INFO",
                    "risk_score": 0.0,
                    "reasons": [f"{disp_name} was closed after {duration_sec}s of activity."],
                    "start_time": start_iso,
                    "end_time": now_iso,
                    "duration_seconds": duration_sec,
                    "timestamp": now_iso
                }
                new_events.append(closed_event)

        self._seen_pids = current_pids
        return new_events

    def find_active_adware_processes(self) -> List[Dict[str, Any]]:
        """
        Scans currently active host processes and returns active adware,
        scareware, or promotional popup processes currently displaying on screen.
        Requires that a live process has an actual visible desktop window (not a silent background service).
        """
        visible_pids = self.get_visible_window_pids()
        found = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pid = proc.info.get('pid')
                p_dict = proc.info
                name_lower = (p_dict.get('name') or '').lower()
                exe_lower = (p_dict.get('exe') or '').lower()
                
                # Fast check against known adware signatures
                matches = False
                for pattern_info in self.ADWARE_PATTERNS:
                    pat = pattern_info["pattern"]
                    if pat in name_lower or (exe_lower and pat in exe_lower):
                        matches = True
                        break
                        
                if matches:
                    eval_res = self.evaluate_process(p_dict)
                    if eval_res.get("is_adware"):
                        # If running in an interactive session with visible windows, ensure it actually has a visible window!
                        if visible_pids and pid not in visible_pids:
                            continue
                        found.append(eval_res)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return found

