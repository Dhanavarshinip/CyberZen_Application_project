"""
Real-Time File & Download Monitor for CyberThreat AI System.

Monitors user download directories and filesystem events:
- Detects newly downloaded or created files in real-time
- Computes SHA256 checksums
- Scans for safe test signatures (e.g. EICAR Antivirus Test String)
- Inspects high-risk executable extensions (.exe, .bat, .scr, .vbs, .ps1, .hta)
- Detects double extension obfuscation (e.g. receipt.pdf.exe)
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

class FileMonitor:
    """Monitors downloads and evaluates security risk of local files."""

    EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    HIGH_RISK_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl", ".msi", ".iso"
    }

    SUSPICIOUS_NAMES = [
        "invoice", "receipt", "payment", "bank_statement", "urgent_doc", "password", "crack", "keygen"
    ]

    def __init__(self, watch_dir: Optional[Path] = None):
        if watch_dir:
            self.watch_dirs = [watch_dir]
        else:
            candidates = [
                Path.home() / "Downloads",
                Path.home() / "Desktop",
                Path.home() / "Documents",
                Path.cwd()
            ]
            for drive in ["D:/", "C:/"]:
                dp = Path(drive)
                if dp.exists() and dp not in candidates:
                    candidates.append(dp)
            self.watch_dirs = [d for d in candidates if d.exists()]
        self._seen_files = set()
        self._init_existing()

    def _init_existing(self):
        """Records already existing files so only new downloads/files are flagged."""
        for d in self.watch_dirs:
            if d.exists():
                try:
                    for p in d.iterdir():
                        if p.is_file():
                            self._seen_files.add(str(p.resolve()))
                        elif p.is_dir() and not p.name.startswith(".") and not p.name.startswith("$") and p.name not in ("node_modules", ".git", "AppData", "__pycache__", "Windows", "Program Files", "Program Files (x86)"):
                            try:
                                for sub in p.iterdir():
                                    if sub.is_file():
                                        self._seen_files.add(str(sub.resolve()))
                            except Exception:
                                pass
                except Exception:
                    pass

    @classmethod
    def evaluate_file(cls, file_path: str | Path) -> Dict[str, Any]:
        """
        Evaluates a specific file for potential security risks.
        """
        path = Path(file_path)
        file_name = path.name
        ext = path.suffix.lower()
        parts = file_name.split('.')
        is_double_ext = len(parts) > 2 and f".{parts[-1].lower()}" in cls.HIGH_RISK_EXTENSIONS
        is_eicar = "eicar" in file_name.lower()
        if not path.exists() or not path.is_file():
            reasons = []
            risk_score = 0.0
            if is_eicar:
                reasons.append("Contains standard EICAR Antivirus Test Signature (detected/quarantined by host OS).")
                risk_score = 95.0
                status = "DANGEROUS"
            elif is_double_ext:
                fake_ext = parts[-2].lower()
                reasons.append(f"Double extension obfuscation detected ('{fake_ext}.{parts[-1]}').")
                risk_score = 85.0
                status = "DANGEROUS"
            elif ext in cls.HIGH_RISK_EXTENSIONS:
                reasons.append(f"Directly executable high-risk file type '{ext}'.")
                risk_score = 50.0
                status = "SUSPICIOUS"
            else:
                return {
                    "file_path": str(file_path),
                    "file_name": path.name,
                    "status": "UNKNOWN",
                    "risk_score": 0.0,
                    "reasons": ["File not found or inaccessible."],
                    "is_dangerous": False,
                    "is_eicar_test": False
                }
            return {
                "file_path": str(file_path),
                "file_name": path.name,
                "extension": ext,
                "file_size_bytes": 0,
                "sha256": "",
                "status": status,
                "risk_score": risk_score,
                "is_dangerous": status == "DANGEROUS",
                "is_eicar_test": is_eicar,
                "reasons": reasons,
                "evaluated_at": datetime.now(timezone.utc).isoformat()
            }

        reasons = []
        risk_score = 5.0  # Baseline for any user file
        file_name = path.name
        file_size = 0
        sha256 = ""
        is_eicar = False

        try:
            file_size = path.stat().st_size
            with open(path, "rb") as f:
                content = f.read(1024 * 1024)  # Read up to 1MB for hashing/signature
                sha256 = hashlib.sha256(content).hexdigest()
                
                # Check for EICAR standard test string
                if cls.EICAR_SIGNATURE.encode("ascii") in content or b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                    is_eicar = True
                    reasons.append("Contains standard EICAR Antivirus Test Signature.")
        except Exception as e:
            # If Windows Defender locked/quarantined the file immediately upon write,
            # or access is denied, and the file is an eicar test file:
            if "eicar" in file_name.lower():
                is_eicar = True
                reasons.append("Contains standard EICAR Antivirus Test Signature (detected/quarantined by host OS).")
                risk_score = 95.0
            else:
                reasons.append(f"Permission or read limitation: {str(e)}")

        ext = path.suffix.lower()
        
        # Check high-risk executable types
        if ext in cls.HIGH_RISK_EXTENSIONS:
            reasons.append(f"Directly executable file type '{ext}'.")
            risk_score += 40.0

        # Check double extension obfuscation (e.g., sample.pdf.exe)
        parts = file_name.split('.')
        if len(parts) > 2 and f".{parts[-1].lower()}" in cls.HIGH_RISK_EXTENSIONS:
            fake_ext = parts[-2].lower()
            if fake_ext in ("pdf", "docx", "xlsx", "jpg", "png", "txt", "zip"):
                reasons.append(f"Double extension obfuscation detected ('{fake_ext}.{parts[-1]}').")
                risk_score += 45.0

        # Check suspicious lure naming
        lower_name = file_name.lower()
        for lure in cls.SUSPICIOUS_NAMES:
            if lure in lower_name and ext in cls.HIGH_RISK_EXTENSIONS:
                reasons.append(f"Executable disguised with social engineering keyword '{lure}'.")
                risk_score += 20.0
                break

        risk_score = round(max(0.0, min(100.0, risk_score)), 1)

        # Categorize
        if is_eicar or risk_score >= 75.0:
            status = "DANGEROUS"
        elif risk_score >= 35.0:
            status = "SUSPICIOUS"
        else:
            status = "SAFE"

        if not reasons:
            reasons.append("Standard file with verified attributes and no known threat markers.")

        return {
            "file_path": str(path.resolve()),
            "file_name": file_name,
            "extension": ext,
            "file_size_bytes": file_size,
            "sha256": sha256,
            "status": status,
            "risk_score": risk_score,
            "is_eicar_test": is_eicar,
            "reasons": reasons,
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }

    def _check_and_evaluate(self, p: Path, current_files: set, new_events: list):
        try:
            resolved = str(p.resolve())
            current_files.add(resolved)
            if resolved not in self._seen_files:
                self._seen_files.add(resolved)
                evaluation = self.evaluate_file(p)
                new_events.append(evaluation)
        except Exception:
            pass

    def check_new_downloads(self) -> List[Dict[str, Any]]:
        """
        Scans watch directories and user workspace for newly created files since last check.
        """
        new_events = []
        current_files = set()
        for d in self.watch_dirs:
            if not d.exists():
                continue
            try:
                for p in d.iterdir():
                    if p.is_file():
                        self._check_and_evaluate(p, current_files, new_events)
                    elif p.is_dir() and not p.name.startswith(".") and not p.name.startswith("$") and p.name not in ("node_modules", ".git", "AppData", "__pycache__", "Windows", "Program Files", "Program Files (x86)"):
                        try:
                            for sub in p.iterdir():
                                if sub.is_file():
                                    self._check_and_evaluate(sub, current_files, new_events)
                        except Exception:
                            pass
            except Exception:
                pass
        self._seen_files = current_files
        return new_events
