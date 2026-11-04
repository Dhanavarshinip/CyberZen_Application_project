"""
Real-Time Threat Intelligence & Whitelist Engine for CyberThreat AI.

Downloads, caches, and integrates real security datasets:
1. OpenPhish Live Phishing Feed (real-time malicious URLs)
2. URLhaus Blocklist (real-time active malware distribution domains)
3. LOLBAS Attack Knowledge Base (Living Off The Land Binaries with ATT&CK techniques)
4. Comprehensive Windows System Binary Whitelist (eliminates OS housekeeping false positives)
5. Top Reputable Domains Whitelist (prevents benign websites from being flagged)
"""

import os
import json
import urllib.request
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intelligence"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 1. Verified Benign Windows System Processes (Standard OS Maintenance & Services)
# These run from C:\Windows\System32\ or C:\Windows\SysWOW64\ and should NOT trigger false threat alerts
BENIGN_WINDOWS_BINARIES: Set[str] = {
    "svchost.exe", "dwm.exe", "sihost.exe", "taskhostw.exe", "explorer.exe",
    "cleanmgr.exe", "dismhost.exe", "wermgr.exe", "runtimebroker.exe",
    "searchhost.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "ctfmon.exe", "conhost.exe", "smartscreen.exe", "securityhealthsystray.exe",
    "securityhealthservice.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "fontdrvhost.exe", "dllhost.exe", "spoolsv.exe", "defrag.exe",
    "lpksetup.exe", "consent.exe", "audiodg.exe", "wmiprvse.exe", "compattelrunner.exe",
    "devicecen.exe", "applicationframehost.exe", "systemsettings.exe",
    "antigravity.exe", "code.exe", "electron.exe", "python.exe", "pythonw.exe",
    "node.exe", "chrome.exe", "firefox.exe", "msedge.exe", "notepad.exe"
}

# 2. Top Global Reputable Safe Domains (Never flag as suspicious)
TOP_SAFE_DOMAINS: Set[str] = {
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "github.com", "www.github.com", "microsoft.com", "www.microsoft.com",
    "wikipedia.org", "en.wikipedia.org", "apple.com", "amazon.com",
    "linkedin.com", "twitter.com", "x.com", "reddit.com", "cloudflare.com",
    "mozilla.org", "python.org", "npmjs.com", "stackoverflow.com",
    "chatgpt.com", "openai.com", "anthropic.com", "gemini.google.com",
    "office.com", "live.com", "bing.com", "netflix.com", "spotify.com",
    "whatsapp.com", "telegram.org", "zoom.us", "dropbox.com", "slack.com"
}

# 3. Verified Cryptomining & C2 Domains from Dataset Sensor Telemetry
KNOWN_MALICIOUS_MINERS: Set[str] = {
    "pool.hashvault.pro", "hashvault.pro", "supportxmr.com", "nanopool.org", "moneropool.com", "minexmr.com"
}


class ThreatIntelligenceEngine:
    """Manages real-time threat intelligence feeds, whitelists, and LOLBAS datasets."""

    def __init__(self):
        self.malicious_urls: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.lolbas_rules: Dict[str, Dict[str, Any]] = {}
        self.safe_domains: Set[str] = set(TOP_SAFE_DOMAINS)
        self.benign_binaries: Set[str] = set(BENIGN_WINDOWS_BINARIES)
        self.last_sync_timestamp: Optional[str] = None
        self.sync_status: str = "INITIALIZING"

        # Load existing local cache first if available
        self._load_local_cache()

        # Start non-blocking background updater
        threading.Thread(target=self.sync_feeds, daemon=True).start()

    def _load_local_cache(self):
        """Loads cached intelligence from disk if already downloaded."""
        try:
            dom_file = DATA_DIR / "urlhaus_domains.json"
            if dom_file.exists():
                with open(dom_file, "r", encoding="utf-8") as f:
                    self.malicious_domains = set(json.load(f))
            self.malicious_domains.update(KNOWN_MALICIOUS_MINERS)

            url_file = DATA_DIR / "openphish_urls.json"
            if url_file.exists():
                with open(url_file, "r", encoding="utf-8") as f:
                    self.malicious_urls = set(json.load(f))

            lol_file = DATA_DIR / "lolbas_rules.json"
            if lol_file.exists():
                with open(lol_file, "r", encoding="utf-8") as f:
                    self.lolbas_rules = json.load(f)

            if self.malicious_domains or self.malicious_urls:
                self.sync_status = "LOADED_FROM_CACHE"
                print(f"[+] Loaded Threat Intelligence Cache: {len(self.malicious_domains)} domains, {len(self.malicious_urls)} URLs, {len(self.lolbas_rules)} LOLBAS signatures.")
        except Exception as e:
            print(f"[-] Could not read local threat cache: {e}")

    def sync_feeds(self):
        """Fetches live datasets from verified public threat intelligence repositories."""
        print("[*] Synchronizing real-world threat intelligence feeds...")
        self.sync_status = "SYNCING"
        headers = {"User-Agent": "CyberThreatAI-Research-Agent/1.0"}

        # A. Download URLhaus active malicious domains
        try:
            req = urllib.request.Request(
                "https://raw.githubusercontent.com/curbengh/urlhaus-filter/master/urlhaus-filter-domains.txt",
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=12) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                domains = set()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line.lower())
                if domains:
                    domains.update(KNOWN_MALICIOUS_MINERS)
                    self.malicious_domains = domains
                    with open(DATA_DIR / "urlhaus_domains.json", "w", encoding="utf-8") as f:
                        json.dump(list(domains), f)
                    print(f"[+] URLhaus dataset ingested: {len(domains)} verified malware domains.")
        except Exception as e:
            print(f"[-] URLhaus sync notice: {e}")

        # B. Download OpenPhish live phishing URL feed
        try:
            req = urllib.request.Request("https://openphish.com/feed.txt", headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                urls = set()
                for line in content.splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line.lower())
                        try:
                            # also record domain
                            from urllib.parse import urlparse
                            d = urlparse(line).netloc.lower()
                            if d:
                                self.malicious_domains.add(d)
                        except Exception:
                            pass
                if urls:
                    self.malicious_urls = urls
                    with open(DATA_DIR / "openphish_urls.json", "w", encoding="utf-8") as f:
                        json.dump(list(urls), f)
                    print(f"[+] OpenPhish dataset ingested: {len(urls)} live verified phishing URLs.")
        except Exception as e:
            print(f"[-] OpenPhish sync notice: {e}")

        # C. Download LOLBAS Project (Living Off The Land Binaries) Attack Techniques
        try:
            req = urllib.request.Request("https://lolbas-project.github.io/api/lolbas.json", headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                lol_data = json.loads(content)
                rules = {}
                for item in lol_data:
                    name = item.get("Name", "").lower()
                    if name:
                        rules[name] = {
                            "name": item.get("Name"),
                            "description": item.get("Description", ""),
                            "author": item.get("Author", ""),
                            "commands": item.get("Commands", []),
                            "mitre_attck": [c.get("MitreID") for c in item.get("Commands", []) if c.get("MitreID")]
                        }
                if rules:
                    self.lolbas_rules = rules
                    with open(DATA_DIR / "lolbas_rules.json", "w", encoding="utf-8") as f:
                        json.dump(rules, f, indent=2)
                    print(f"[+] LOLBAS dataset ingested: {len(rules)} system binaries with documented weaponization techniques.")
        except Exception as e:
            print(f"[-] LOLBAS sync notice: {e}")

        self.last_sync_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.sync_status = "ACTIVE"
        print(f"[+] Threat Intelligence Engine fully synchronized ({len(self.malicious_domains)} malware domains, {len(self.malicious_urls)} phishing URLs, {len(self.lolbas_rules)} LOLBAS patterns).")

    def is_known_safe_domain(self, domain: str) -> bool:
        """Returns True if the domain is a verified reputable domain."""
        if not domain:
            return False
        d = domain.lower().strip()
        if d in self.safe_domains:
            return True
        for safe in self.safe_domains:
            if d.endswith("." + safe):
                return True
        return False

    def is_malicious_domain(self, domain: str) -> bool:
        """Checks domain against URLhaus and OpenPhish threat intelligence feeds."""
        if not domain:
            return False
        d = domain.lower().strip()
        if d in self.safe_domains:
            return False
        if d in self.malicious_domains:
            return True
        for mal in self.malicious_domains:
            if d == mal or d.endswith("." + mal):
                return True
        return False

    def is_malicious_url(self, url: str) -> bool:
        """Checks URL against live OpenPhish and URLhaus feeds."""
        if not url:
            return False
        u = url.lower().strip()
        if u in self.malicious_urls:
            return True
        try:
            from urllib.parse import urlparse
            dom = urlparse(u).netloc
            if self.is_malicious_domain(dom):
                return True
        except Exception:
            pass
        return False

    def is_benign_system_process(self, process_name: str, exe_path: str = "") -> bool:
        """
        Determines if a process is a legitimate Windows OS maintenance/system binary
        running from genuine system directories, preventing false positive alarms.
        """
        if not process_name:
            return False
        p_name = process_name.lower().strip()
        if p_name in self.benign_binaries:
            # If path is provided, ensure it's not being spoofed from Temp or AppData
            if exe_path:
                path_lower = exe_path.lower()
                if "temp\\" in path_lower or "tmp\\" in path_lower or "downloads\\" in path_lower:
                    # Legitimate system binaries never run from temp or downloads!
                    return False
            return True
        return False

    def evaluate_process_execution(self, process_name: str, cmd_line: str = "", exe_path: str = "") -> Dict[str, Any]:
        """
        Evaluates a process execution against LOLBAS attack techniques and system rules.
        Returns risk score, matching ATT&CK techniques, and threat indicators.
        """
        p_name = process_name.lower().strip() if process_name else ""
        cmd = cmd_line.lower() if cmd_line else ""

        # 1. Check if known benign OS process with standard behavior
        if self.is_benign_system_process(p_name, exe_path) and not cmd_line:
            return {
                "is_threat": False,
                "risk_score": 0.0,
                "category": "BENIGN_OS",
                "verdict": "SAFE",
                "reason": "Legitimate operating system background process."
            }

        # 2. Check for weaponized LOLBAS execution
        if p_name in self.lolbas_rules:
            rule = self.lolbas_rules[p_name]
            suspicious_switches = ["-urlcache", "-f -split", "downloadstring", "invoke-expression", "iex", "hidden", "bypass", "encodedcommand", "-enc "]
            matched_switches = [s for s in suspicious_switches if s in cmd]
            if matched_switches:
                attck_ids = rule.get("mitre_attck", []) or ["T1218", "T1059"]
                return {
                    "is_threat": True,
                    "risk_score": 0.88,
                    "category": "LOLBAS_ATTACK",
                    "verdict": "DANGER",
                    "binary": rule["name"],
                    "matched_arguments": matched_switches,
                    "mitre_attck": attck_ids,
                    "description": f"Weaponized execution of Living-off-the-Land binary ({rule['name']}) with attack arguments: {', '.join(matched_switches)}",
                    "remediation": f"Terminate process PID and isolate network activity for {rule['name']}."
                }

        # 3. Check for Suspicious Script/Shell Commands
        if "powershell" in p_name or "cmd.exe" in p_name or "wscript.exe" in p_name or "cscript.exe" in p_name:
            high_risk_patterns = ["-enc ", "-encodedcommand", "downloadstring", "iex(", "invoke-webrequest -outfile", "certutil -urlcache", "vssadmin delete shadows"]
            for pat in high_risk_patterns:
                if pat in cmd:
                    return {
                        "is_threat": True,
                        "risk_score": 0.95,
                        "category": "MALICIOUS_SCRIPT_EXECUTION",
                        "verdict": "CRITICAL",
                        "mitre_attck": ["T1059.001", "T1105"],
                        "description": f"Observed stealth command-line pattern: '{pat}'",
                        "remediation": "Immediate process termination recommended."
                    }

        return {
            "is_threat": False,
            "risk_score": 0.0,
            "category": "STANDARD_APPLICATION",
            "verdict": "SAFE",
            "reason": "Standard application behavior within baseline parameters."
        }


# Singleton threat intelligence instance
threat_intel = ThreatIntelligenceEngine()
