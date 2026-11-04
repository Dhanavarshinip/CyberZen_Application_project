"""
Real-Time Network Connection Monitor for CyberThreat AI System.

Inspects active host network sockets and remote endpoints using legitimate OS APIs (psutil):
- Identifies remote IP addresses, ports, and protocols
- Maps socket connections to local source processes
- Identifies unusual non-standard egress ports (e.g. 4444, 1337, 6667)
- Detects connections to suspicious / high-risk endpoints
"""

import ipaddress
import psutil
from typing import Dict, Any, List
from datetime import datetime, timezone

class NetworkMonitor:
    """Monitors live network connections on the host machine."""

    HIGH_RISK_PORTS = {4444, 1337, 6667, 31337, 8888, 9999, 5555}

    def __init__(self):
        self._seen_conns = set()
        self._init_current_connections()

    def _init_current_connections(self):
        """Records initial active connections on startup."""
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr:
                    key = (conn.pid, conn.laddr.port if conn.laddr else 0, conn.raddr.ip, conn.raddr.port)
                    self._seen_conns.add(key)
        except Exception:
            pass

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Determines whether an IP address is local / RFC 1918 private."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            # Only RFC 1918, loopback, and link-local are considered internal private
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    @classmethod
    def evaluate_connection(cls, conn_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a network connection for suspicious characteristics.
        """
        r_ip = conn_dict.get("remote_ip", "")
        r_port = int(conn_dict.get("remote_port", 0) or 0)
        proc_name = conn_dict.get("process_name", "unknown")
        status = conn_dict.get("status", "ESTABLISHED")

        reasons = []
        risk_score = 0.0

        is_internal = cls._is_private_ip(r_ip) if r_ip else True

        if r_ip and not is_internal:
            risk_score += 5.0  # External internet connection

        # Check high-risk egress ports (e.g. 4444 Metasploit, 1337, etc.)
        if r_port in cls.HIGH_RISK_PORTS:
            reasons.append(f"Connection to high-risk port {r_port} commonly used by command-and-control frameworks.")
            risk_score += 65.0

        # Check if suspicious process/command interpreter initiated the connection
        if proc_name.lower() in ("cmd.exe", "powershell.exe", "powershell_remote.exe", "nc.exe"):
            reasons.append(f"Command interpreter ({proc_name}) established network socket to {r_ip}:{r_port}.")
            risk_score += 50.0

        risk_score = round(max(0.0, min(100.0, risk_score)), 1)

        if risk_score >= 70.0:
            status_threat = "DANGEROUS"
        elif risk_score >= 35.0:
            status_threat = "SUSPICIOUS"
        elif r_ip and not is_internal:
            status_threat = "SAFE"
        else:
            status_threat = "INFO"

        if not reasons:
            reasons.append(f"Network connection to {r_ip}:{r_port} ({proc_name}).")

        return {
            "pid": conn_dict.get("pid", 0),
            "process_name": proc_name,
            "local_ip": conn_dict.get("local_ip", ""),
            "local_port": conn_dict.get("local_port", 0),
            "remote_ip": r_ip,
            "remote_port": r_port,
            "protocol": conn_dict.get("type", "TCP"),
            "status": status,
            "threat_status": status_threat,
            "risk_score": risk_score,
            "reasons": reasons,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def check_new_connections(self, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Detects newly established connections since last poll.
        """
        new_events = []
        current_keys = set()
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if not conn.raddr:
                    continue
                r_ip = conn.raddr.ip
                if r_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                    continue
                r_port = conn.raddr.port
                l_port = conn.laddr.port if conn.laddr else 0
                pid = conn.pid or 0
                key = (pid, l_port, r_ip, r_port)
                current_keys.add(key)

                if key not in self._seen_conns:
                    self._seen_conns.add(key)
                    proc_name = "System"
                    if pid:
                        try:
                            proc_name = psutil.Process(pid).name()
                        except Exception:
                            proc_name = "unknown"

                    c_info = {
                        "pid": pid,
                        "process_name": proc_name,
                        "local_ip": conn.laddr.ip if conn.laddr else "",
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "type": "TCP" if conn.type == psutil.SOCK_STREAM else "UDP",
                        "status": conn.status
                    }
                    evaluation = self.evaluate_connection(c_info)
                    new_events.append(evaluation)
                    if len(new_events) >= limit:
                        break

            self._seen_conns = current_keys
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception:
            pass

        return new_events

    @classmethod
    def scan_active_connections(cls, limit: int = 30) -> List[Dict[str, Any]]:
        """
        Scans current network connections on the host machine.
        """
        results = []
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if not conn.raddr:
                    continue
                    
                pid = conn.pid or 0
                proc_name = "unknown"
                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                    except Exception:
                        pass

                c_info = {
                    "pid": pid,
                    "process_name": proc_name,
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": conn.laddr.port if conn.laddr else 0,
                    "remote_ip": conn.raddr.ip if conn.raddr else "",
                    "remote_port": conn.raddr.port if conn.raddr else 0,
                    "type": "TCP" if conn.type == psutil.SOCK_STREAM else "UDP",
                    "status": conn.status
                }
                
                evaluation = cls.evaluate_connection(c_info)
                results.append(evaluation)
                if len(results) >= limit:
                    break
        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception:
            pass

        return results

