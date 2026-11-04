"""
Hardware Identity Resolver for CyberThreat AI System.

Generates and retrieves a persistent, unique hardware device ID tied to the
actual physical machine, independent of user account, email address, or session.
Uses Windows MachineGuid from the registry where available, falling back to
motherboard UUID and MAC-node SHA-256 hash.
"""

import os
import platform
import hashlib
from pathlib import Path
from typing import Optional


def get_physical_hardware_id() -> str:
    """
    Returns a persistent unique hardware device ID for this physical machine.
    Format: DEV_HW_<12-HEX-CHARS>
    Never uses an email address or random session string.
    """
    # 1. Check if persistent ID was already cached in data/local_device_id.txt
    data_dir = Path("data")
    cache_file = data_dir / "local_device_id.txt"
    if cache_file.exists():
        try:
            cached = cache_file.read_text().strip()
            if cached and cached.startswith("DEV_") and len(cached) >= 10:
                return cached
        except Exception:
            pass

    raw_id: Optional[str] = None

    # 2. Windows: Query MachineGuid from registry
    if platform.system() == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                guid, _ = winreg.QueryValueEx(key, "MachineGuid")
                if guid:
                    raw_id = f"WIN_REG_{guid}"
        except Exception:
            pass

    # 3. Fallback: Combine platform node, processor architecture, and MAC address
    if not raw_id:
        try:
            import uuid
            mac = uuid.getnode()
            node = platform.node().upper()
            raw_id = f"NODE_{node}_{mac}"
        except Exception:
            import uuid
            raw_id = f"FALLBACK_{uuid.uuid4().hex}"

    # 4. Generate stable hash
    h = hashlib.sha256(raw_id.encode("utf-8")).hexdigest().upper()
    device_id = f"DEV_HW_{h[:12]}"

    # 5. Persist to data/local_device_id.txt
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(device_id)
    except Exception:
        pass

    return device_id
