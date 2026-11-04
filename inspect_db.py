import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from backend.config import Config
import sqlite3

print("Config.DB_PATH:", Config.DB_PATH)
conn = sqlite3.connect(str(Config.DB_PATH))
conn.row_factory = sqlite3.Row

print("\n--- USERS ---")
for u in conn.execute("SELECT id, name, email FROM users").fetchall():
    print(dict(u))

print("\n--- DEVICES ---")
for d in conn.execute("SELECT device_id, user_id, device_name, os_info FROM devices").fetchall():
    print(dict(d))
