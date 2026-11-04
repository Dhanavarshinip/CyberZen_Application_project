import sqlite3
from datetime import datetime, timezone
conn = sqlite3.connect(r'D:\CyberThreat_AI_System\data\cyberthreat.db')
cur = conn.cursor()
now_iso = datetime.now(timezone.utc).isoformat()
user_row = cur.execute("SELECT id FROM users WHERE email = 'varshinid056@gmail.com'").fetchone()
if user_row:
    uid = user_row[0]
    cur.execute("DELETE FROM devices WHERE user_id = ? AND device_name LIKE '%LAPTOP%'", (uid,))
    cur.execute("DELETE FROM devices WHERE user_id = ? AND device_id LIKE 'DEV_24%'", (uid,))
    cur.execute("DELETE FROM devices WHERE device_id = 'DEV_DESKTOP-CLE9N5A'")
    cur.execute("""
        INSERT INTO devices (device_id, user_id, device_name, os_info, status, last_seen, created_at, is_revoked)
        VALUES ('DEV_DESKTOP-CLE9N5A', ?, 'DESKTOP-CLE9N5A', 'Windows 11 (AMD64)', 'ONLINE', ?, ?, 0)
    """, (uid, now_iso, now_iso))
    conn.commit()
    print("Device registration successfully bound to DESKTOP-CLE9N5A for", uid)
print("Current devices:")
for d in cur.execute("SELECT device_id, user_id, device_name, status FROM devices").fetchall():
    print(d)
conn.close()
