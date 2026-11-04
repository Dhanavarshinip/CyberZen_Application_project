"""
Backfills all existing events in data/cyberthreat.db with activity_domain ('ONLINE' vs 'OFFLINE')
and SQLite storage verification metadata.
"""

import sqlite3
import json
from pathlib import Path

db_path = Path("data") / "cyberthreat.db"
if not db_path.exists():
    print(f"[-] Database {db_path} does not exist.")
    exit(0)

conn = sqlite3.connect(str(db_path))
c = conn.cursor()
c.execute("SELECT event_id, event_type, features, sync_status FROM events")
rows = c.fetchall()

updated = 0
online_count = 0
offline_count = 0

for eid, ev_type, feat_json, sync_st in rows:
    try:
        f = json.loads(feat_json) if feat_json else {}
    except Exception:
        f = {}

    is_online = (
        ev_type in ("WEBSITE_OPENED", "BROWSER_NAVIGATION", "NETWORK_CONNECTION")
        or bool(f.get("domain"))
        or bool(f.get("url"))
        or (bool(f.get("remote_ip")) and f.get("remote_ip") not in ("127.0.0.1", "::1", "localhost"))
        or f.get("activity_category") in ("Browser", "Websites", "Network")
    )
    domain = "ONLINE" if is_online else "OFFLINE"
    if domain == "ONLINE":
        online_count += 1
    else:
        offline_count += 1

    f["activity_domain"] = domain
    f["connectivity_state"] = "ONLINE" if sync_st == "SYNCHRONIZED" else "OFFLINE"
    f["storage_table"] = "events"
    f["db_path"] = "data/cyberthreat.db"
    f["db_storage_confirmed"] = True

    c.execute("UPDATE events SET features = ? WHERE event_id = ?", (json.dumps(f), eid))
    updated += 1

conn.commit()
print(f"[+] Successfully backfilled {updated} events in {db_path}.")
print(f"[+] ONLINE activities: {online_count}")
print(f"[+] OFFLINE activities: {offline_count}")
conn.close()
