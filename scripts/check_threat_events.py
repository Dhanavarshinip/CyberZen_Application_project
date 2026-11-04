import sqlite3
import json
import urllib.request

con = sqlite3.connect('data/cyberthreat.db')
cur = con.cursor()
rows = cur.execute("SELECT event_id, event_type, risk_score, features FROM events WHERE risk_score >= 50 OR features LIKE '%DANGEROUS%'").fetchall()
print(f"Found {len(rows)} dangerous/elevated events in DB:")
for r in rows:
    print(f"  ID: {r[0]}, Type: {r[1]}, Risk: {r[2]}")
    try:
        f = json.loads(r[3])
        print(f"    Desc: {f.get('description')}, Status: {f.get('status')}")
    except Exception:
        print(f"    Features: {r[3][:100]}")

# Also check /api/device/status or /api/devices/{id}/status
try:
    req = urllib.request.urlopen("http://127.0.0.1:8000/api/dashboard", timeout=3)
    data = json.loads(req.read().decode())
    print("\nDashboard status:", data.get("system_status"), data.get("threat_level"))
except Exception as e:
    print("\nAPI check error:", e)
