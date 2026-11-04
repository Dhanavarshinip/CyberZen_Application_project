"""
Cleans synthetic test incidents and background noise from cyberthreat.db.
Preserves authentic user records while purging false positive test clusters.
"""
import sqlite3
from pathlib import Path

db_path = Path("data") / "cyberthreat.db"
if db_path.exists():
    con = sqlite3.connect(str(db_path))
    cur = con.cursor()

    cur.execute("SELECT COUNT(*) FROM incidents")
    before_incidents = cur.fetchone()[0]

    # Delete incidents containing synthetic test data or maintenance clutter
    cur.execute("""
        DELETE FROM incidents
        WHERE summary LIKE '%paypal-support%'
           OR summary LIKE '%Computer security%'
           OR details_json LIKE '%paypal-support%'
           OR details_json LIKE '%cleanmgr%'
           OR details_json LIKE '%dismhost%'
           OR details_json LIKE '%Wikipedia%'
    """)
    con.commit()

    cur.execute("SELECT COUNT(*) FROM events")
    before_events = cur.fetchone()[0]

    cur.execute("""
        DELETE FROM events
        WHERE event_type LIKE 'TEST_%'
           OR features LIKE '%"is_test_event": true%'
           OR features LIKE '%"is_test_event":true%'
           OR features LIKE '%spoofed sender: paypal-support%'
    """)
    con.commit()

    # Clean up repetitive internal OS maintenance events
    cur.execute("""
        DELETE FROM events
        WHERE event_type IN ('APPLICATION_START', 'APPLICATION_CLOSED')
          AND (
            features LIKE '%cleanmgr%'
            OR features LIKE '%dismhost%'
            OR features LIKE '%wermgr%'
            OR features LIKE '%lpksetup%'
            OR features LIKE '%defrag%'
            OR features LIKE '%consent%'
            OR features LIKE '%crashhelper%'
          )
    """)
    con.commit()

    cur.execute("SELECT COUNT(*) FROM incidents")
    after_incidents = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM events")
    after_events = cur.fetchone()[0]

    print(f"[+] Database cleaned successfully!")
    print(f"    Incidents: {before_incidents} -> {after_incidents}")
    print(f"    Events:    {before_events} -> {after_events}")
    con.close()
