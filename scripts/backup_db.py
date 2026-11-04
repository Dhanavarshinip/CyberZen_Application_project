"""
Automated Database Backup and Integrity Verification Script for CyberThreat AI.

Safely copies the local or cloud SQLite database with WAL checkpointing,
generates a timestamped backup, computes SHA-256 integrity hash,
and prunes backups older than retention policy.
"""

import os
import shutil
import sqlite3
import hashlib
from datetime import datetime, timezone
from pathlib import Path

def backup_database(db_path_str: str = "data/cyberthreat.db", backup_dir_str: str = "data/backups", max_retention: int = 10):
    db_path = Path(db_path_str)
    backup_dir = Path(backup_dir_str)
    backup_dir.mkdir(parents=True, exist_ok=True)

    if not db_path.exists():
        print(f"[-] Database file not found at {db_path}")
        return False

    now_tag = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest_path = backup_dir / f"cyberthreat_backup_{now_tag}.db"

    print(f"[*] Starting database backup from {db_path} to {dest_path}...")

    # Flush WAL into main database file cleanly before copying
    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
    except Exception as e:
        print(f"[!] Warning: WAL checkpoint flush encountered: {e}")

    # Create backup copy using SQLite backup API for 100% atomic consistency
    src_conn = sqlite3.connect(str(db_path))
    dst_conn = sqlite3.connect(str(dest_path))
    with dst_conn:
        src_conn.backup(dst_conn)
    dst_conn.close()
    src_conn.close()

    # Calculate integrity SHA-256
    hasher = hashlib.sha256()
    with open(dest_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    backup_sha = hasher.hexdigest()

    sz_bytes = dest_path.stat().st_size
    sz_mb = round(sz_bytes / (1024 * 1024), 2)

    print(f"[+] Backup completed successfully: {dest_path.name}")
    print(f"    Size: {sz_mb} MB ({sz_bytes} bytes)")
    print(f"    SHA-256: {backup_sha}")

    # Prune old backups
    existing_backups = sorted(backup_dir.glob("cyberthreat_backup_*.db"), key=lambda p: p.stat().st_mtime)
    if len(existing_backups) > max_retention:
        to_remove = existing_backups[:-max_retention]
        for p in to_remove:
            try:
                p.unlink()
                print(f"[-] Pruned aged backup: {p.name}")
            except Exception:
                pass

    return True

if __name__ == "__main__":
    backup_database()
