import sqlite3

con = sqlite3.connect('data/cyberthreat.db')
cur = con.cursor()
stale_ids = ['evt_threat_82c41d63', 'evt_web_be6e30a5ff', 'ev_test_c8056f', 'ev_api_g_586347']
cur.execute("DELETE FROM events WHERE event_id IN (?, ?, ?, ?)", stale_ids)
con.commit()
print(f"Purged {cur.rowcount} stale test events from cyberthreat.db.")
con.close()
