import os, sys
sys.path.insert(0, r"D:\CyberThreat_AI_System")
from backend.config import Config
import sqlite3

for db_p in ['D:/CyberThreat_AI_System/data/cyberthreat.db', 'D:/CyberThreat_AI_System/backend/cyberthreat.db']:
    print("=== Checking:", db_p)
    conn = sqlite3.connect(db_p)
    c = conn.cursor()
    c.execute("SELECT count(*) FROM events")
    print("Total events:", c.fetchone()[0])
    c.execute("SELECT device_id, count(*) FROM events GROUP BY device_id")
    print("By device:", c.fetchall())
    c.execute("SELECT user_id, count(*) FROM events GROUP BY user_id")
    print("By user:", c.fetchall())
    c.execute("SELECT substr(timestamp, 1, 10), count(*) FROM events GROUP BY 1 ORDER BY 1 DESC LIMIT 10")
    print("By date:", c.fetchall())



