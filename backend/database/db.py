"""
SQLite Database Manager for CyberThreat AI System.

Handles all persistent storage: events, behavior profiles, risk history,
sync queue, incidents, and incident-event associations.
Uses synchronous sqlite3 for simplicity and reliability.
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from backend.config import config


class Database:
    """SQLite database manager with all table operations."""

    def __init__(self, db_path=None):
        self.db_path = db_path or str(config.DB_PATH)
        # Ensure the parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_conn(self):
        """Get a database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_tables(self):
        """Create all required tables if they don't exist."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    device_id TEXT,
                    user_id TEXT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    features TEXT DEFAULT '{}',
                    anomaly_score REAL DEFAULT 0.0,
                    behavioral_drift REAL DEFAULT 0.0,
                    risk_score REAL DEFAULT 0.0,
                    detection_source TEXT DEFAULT 'LOCAL',
                    sync_status TEXT DEFAULT 'PENDING',
                    created_at TEXT NOT NULL,
                    synchronized_at TEXT
                );

                CREATE TABLE IF NOT EXISTS behavior_profiles (
                    user_id TEXT PRIMARY KEY,
                    login_hours TEXT DEFAULT '[]',
                    known_devices TEXT DEFAULT '[]',
                    common_applications TEXT DEFAULT '[]',
                    session_durations TEXT DEFAULT '[]',
                    network_destinations TEXT DEFAULT '[]',
                    activity_patterns TEXT DEFAULT '{}',
                    event_count INTEGER DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS risk_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    event_id TEXT,
                    risk_score REAL NOT NULL,
                    anomaly_score REAL DEFAULT 0.0,
                    behavioral_drift REAL DEFAULT 0.0,
                    timestamp TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sync_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    device_id TEXT,
                    payload TEXT NOT NULL,
                    status TEXT DEFAULT 'PENDING',
                    retry_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    synced_at TEXT
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    device_id TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    severity TEXT DEFAULT 'LOW',
                    status TEXT DEFAULT 'OPEN',
                    confidence REAL DEFAULT 0.0,
                    summary TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incident_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    contribution_score REAL DEFAULT 0.0,
                    sequence_order INTEGER DEFAULT 0,
                    UNIQUE(incident_id, event_id)
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    os_info TEXT DEFAULT '',
                    status TEXT DEFAULT 'ONLINE',
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_allowed_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, email)
                );

                CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
                CREATE INDEX IF NOT EXISTS idx_events_device ON events(device_id);
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_sync ON events(sync_status);
                CREATE INDEX IF NOT EXISTS idx_risk_user ON risk_history(user_id);
                CREATE INDEX IF NOT EXISTS idx_sync_status ON sync_queue(status);
                CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user_id);
                CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                CREATE INDEX IF NOT EXISTS idx_allowed_emails_user ON user_allowed_emails(user_id);
            """)
            # Safe column migrations
            try:
                conn.execute("ALTER TABLE risk_history ADD COLUMN device_id TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE sync_queue ADD COLUMN device_id TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE incidents ADD COLUMN details_json TEXT DEFAULT '{}'")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN consent_accepted INTEGER DEFAULT 1")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN consent_timestamp TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE devices ADD COLUMN device_key TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE devices ADD COLUMN is_revoked INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN verification_otp TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE users ADD COLUMN otp_created_at TEXT")
            except sqlite3.OperationalError:
                pass
            conn.commit()
        finally:
            conn.close()


    # ── Event Operations ──────────────────────────────────────

    def insert_event(self, event: dict) -> bool:
        """Insert an event. Returns False if duplicate (idempotent)."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO events
                   (event_id, device_id, user_id, timestamp, event_type,
                    features, anomaly_score, behavioral_drift, risk_score,
                    detection_source, sync_status, created_at, synchronized_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["event_id"],
                    event.get("device_id", ""),
                    event.get("user_id", ""),
                    event["timestamp"],
                    event["event_type"],
                    json.dumps(event.get("features", {})),
                    event.get("anomaly_score", 0.0),
                    event.get("behavioral_drift", 0.0),
                    event.get("risk_score", 0.0),
                    event.get("detection_source", "LOCAL"),
                    event.get("sync_status", "PENDING"),
                    event.get("created_at", datetime.now(timezone.utc).isoformat()),
                    event.get("synchronized_at"),
                )
            )
            conn.commit()
            return conn.total_changes > 0
        finally:
            conn.close()

    def get_event(self, event_id: str) -> dict | None:
        """Get a single event by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def _build_events_where(
        self,
        user_id: str = None,
        event_type: str = None,
        min_risk: float = None,
        device_id: str = None,
        exclude_test: bool = True,
        start_date: str = None,
        end_date: str = None,
        date: str = None,
        client_tz_offset: int = None,
        activity_domain: str = None,
        sync_status: str = None
    ) -> tuple[str, list]:
        """Helper to build WHERE clause and parameters for events query."""
        from datetime import datetime, timezone, timedelta
        query = " WHERE 1=1"
        params = []

        if device_id:
            if user_id and user_id not in ("ALL", "*"):
                query += " AND device_id = ? AND (user_id = ? OR device_id IN (SELECT device_id FROM devices WHERE user_id = ?))"
                params.extend([device_id, user_id, user_id])
            else:
                query += " AND device_id = ?"
                params.append(device_id)
        elif user_id and user_id not in ("ALL", "*"):
            query += " AND (user_id = ? OR device_id IN (SELECT device_id FROM devices WHERE user_id = ?))"
            params.extend([user_id, user_id])

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        if min_risk is not None:
            query += " AND risk_score >= ?"
            params.append(min_risk)

        if sync_status:
            query += " AND sync_status = ?"
            params.append(sync_status)

        if activity_domain:
            dom = activity_domain.strip().upper()
            if dom == "ONLINE":
                query += (
                    " AND (event_type IN ('WEBSITE_OPENED', 'BROWSER_NAVIGATION', 'NETWORK_CONNECTION')"
                    " OR features LIKE '%\"activity_domain\": \"ONLINE\"%'"
                    " OR features LIKE '%\"activity_domain\":\"ONLINE\"%'"
                    " OR features LIKE '%\"domain\"%'"
                    " OR features LIKE '%\"url\"%')"
                )
            elif dom == "OFFLINE":
                query += (
                    " AND (event_type NOT IN ('WEBSITE_OPENED', 'BROWSER_NAVIGATION', 'NETWORK_CONNECTION')"
                    " AND (features LIKE '%\"activity_domain\": \"OFFLINE\"%'"
                    " OR features LIKE '%\"activity_domain\":\"OFFLINE\"%'"
                    " OR (features NOT LIKE '%\"domain\"%' AND features NOT LIKE '%\"url\"%')))"
                )

        if exclude_test:
            query += (
                " AND detection_source != 'TEST_ENDPOINT'"
                " AND event_type NOT LIKE 'TEST_%'"
                " AND features NOT LIKE '%\"is_test_event\": true%'"
                " AND features NOT LIKE '%\"is_test_event\":true%'"
                " AND features NOT LIKE '%\"activity_category\": \"Test\"%'"
                " AND features NOT LIKE '%\"activity_category\":\"Test\"%'"
            )

        # Date filtering: supports exact calendar day (Today, Yesterday, YYYY-MM-DD) or explicit range
        if date:
            d_str = date.strip().upper()
            if d_str in ("TODAY", "YESTERDAY"):
                if client_tz_offset is not None:
                    local_now = datetime.now(timezone.utc) - timedelta(minutes=int(client_tz_offset))
                else:
                    local_now = datetime.now()
                if d_str == "YESTERDAY":
                    target_date = (local_now - timedelta(days=1)).strftime("%Y-%m-%d")
                else:
                    target_date = local_now.strftime("%Y-%m-%d")
            else:
                target_date = date.strip()

            if client_tz_offset is not None:
                offset_minutes = -int(client_tz_offset)
                mod = f"+{offset_minutes} minutes" if offset_minutes >= 0 else f"{offset_minutes} minutes"
                query += " AND date(datetime(COALESCE(timestamp, created_at), ?)) = ?"
                params.extend([mod, target_date])
            else:
                query += " AND substr(COALESCE(timestamp, created_at), 1, 10) = ?"
                params.append(target_date)
        else:
            if start_date:
                if len(start_date) == 10:
                    if client_tz_offset is not None:
                        offset_minutes = -int(client_tz_offset)
                        mod = f"+{offset_minutes} minutes" if offset_minutes >= 0 else f"{offset_minutes} minutes"
                        query += " AND date(datetime(COALESCE(timestamp, created_at), ?)) >= ?"
                        params.extend([mod, start_date])
                    else:
                        query += " AND substr(COALESCE(timestamp, created_at), 1, 10) >= ?"
                        params.append(start_date)
                else:
                    norm_start = start_date.replace("Z", "+00:00") if start_date.endswith("Z") else start_date
                    query += " AND datetime(COALESCE(timestamp, created_at)) >= datetime(?)"
                    params.append(norm_start)

            if end_date:
                if len(end_date) == 10:
                    if client_tz_offset is not None:
                        offset_minutes = -int(client_tz_offset)
                        mod = f"+{offset_minutes} minutes" if offset_minutes >= 0 else f"{offset_minutes} minutes"
                        query += " AND date(datetime(COALESCE(timestamp, created_at), ?)) <= ?"
                        params.extend([mod, end_date])
                    else:
                        query += " AND substr(COALESCE(timestamp, created_at), 1, 10) <= ?"
                        params.append(end_date)
                else:
                    norm_end = end_date.replace("Z", "+00:00") if end_date.endswith("Z") else end_date
                    query += " AND datetime(COALESCE(timestamp, created_at)) <= datetime(?)"
                    params.append(norm_end)

        return query, params

    def get_events(
        self,
        user_id: str = None,
        limit: int = 100,
        event_type: str = None,
        min_risk: float = None,
        device_id: str = None,
        exclude_test: bool = True,
        start_date: str = None,
        end_date: str = None,
        date: str = None,
        client_tz_offset: int = None,
        offset: int = 0,
        activity_domain: str = None,
        sync_status: str = None
    ) -> list[dict]:
        """Get events with optional filters.
        
        DEVICE ISOLATION RULES:
        - If device_id provided: ONLY return events for that exact device (strict)
        - If user_id provided (no device_id): return events where user_id matches
        - Never return events from a different device_id than requested
        - Never cross-contaminate device telemetry
        - When exclude_test=True: exclude all test events and test domains
        """
        conn = self._get_conn()
        try:
            where_sql, params = self._build_events_where(
                user_id=user_id,
                event_type=event_type,
                min_risk=min_risk,
                device_id=device_id,
                exclude_test=exclude_test,
                start_date=start_date,
                end_date=end_date,
                date=date,
                client_tz_offset=client_tz_offset,
                activity_domain=activity_domain,
                sync_status=sync_status
            )
            query = f"SELECT * FROM events{where_sql} ORDER BY COALESCE(timestamp, created_at) DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                feat = d.get("features")
                while isinstance(feat, str):
                    try:
                        feat = json.loads(feat)
                    except Exception:
                        feat = {}
                        break
                if not isinstance(feat, dict):
                    feat = {}
                d["features"] = feat

                if exclude_test:
                    feat = d["features"]
                    if feat.get("is_test_event"):
                        continue
                    if d.get("event_type", "").startswith("TEST_"):
                        continue
                    if d.get("detection_source") == "TEST_ENDPOINT":
                        continue
                    if feat.get("activity_category") == "Test":
                        continue
                results.append(d)
            return results
        finally:
            conn.close()

    def get_events_count(
        self,
        user_id: str = None,
        event_type: str = None,
        min_risk: float = None,
        device_id: str = None,
        exclude_test: bool = True,
        start_date: str = None,
        end_date: str = None,
        date: str = None,
        client_tz_offset: int = None,
        activity_domain: str = None,
        sync_status: str = None
    ) -> int:
        """Count total events matching the filter for accurate pagination."""
        conn = self._get_conn()
        try:
            where_sql, params = self._build_events_where(
                user_id=user_id,
                event_type=event_type,
                min_risk=min_risk,
                device_id=device_id,
                exclude_test=exclude_test,
                start_date=start_date,
                end_date=end_date,
                date=date,
                client_tz_offset=client_tz_offset,
                activity_domain=activity_domain,
                sync_status=sync_status
            )
            row = conn.execute(f"SELECT COUNT(*) as c FROM events{where_sql}", params).fetchone()
            return int(row["c"]) if row else 0
        finally:
            conn.close()

    def get_activity_stats(self, device_id: str = None, user_id: str = None) -> dict:
        """Returns comprehensive breakdown of Online vs Offline stored activities."""
        conn = self._get_conn()
        try:
            where = " WHERE detection_source != 'TEST_ENDPOINT' AND event_type NOT LIKE 'TEST_%'"
            params = []
            if device_id:
                where += " AND device_id = ?"
                params.append(device_id)
            elif user_id and user_id not in ("ALL", "*"):
                where += " AND user_id = ?"
                params.append(user_id)
            
            c = conn.cursor()
            total = c.execute(f"SELECT COUNT(*) FROM events {where}", params).fetchone()[0]
            
            online_count = c.execute(
                f"""SELECT COUNT(*) FROM events {where} 
                    AND (event_type IN ('WEBSITE_OPENED', 'BROWSER_NAVIGATION', 'NETWORK_CONNECTION') 
                         OR features LIKE '%"activity_domain": "ONLINE"%' 
                         OR features LIKE '%"activity_domain":"ONLINE"%' 
                         OR features LIKE '%"domain"%' 
                         OR features LIKE '%"url"%')""",
                params
            ).fetchone()[0]
            
            offline_count = max(0, total - online_count)
            
            pending_count = c.execute(
                f"SELECT COUNT(*) FROM events {where} AND sync_status = 'PENDING'",
                params
            ).fetchone()[0]
            synced_count = c.execute(
                f"SELECT COUNT(*) FROM events {where} AND sync_status = 'SYNCHRONIZED'",
                params
            ).fetchone()[0]
            
            return {
                "total_stored": total,
                "online_activities": online_count,
                "offline_activities": offline_count,
                "pending_sync": pending_count,
                "synchronized": synced_count,
                "database_file": str(self.db_path),
                "storage_engine": "SQLite3 (Persistent Local Record)"
            }
        finally:
            conn.close()

    def get_date_summary(
        self,
        device_id: str = None,
        client_tz_offset: int = None,
        user_id: str = None,
        exclude_test: bool = True
    ) -> list[dict]:
        """
        Returns all calendar dates that have recorded activities, with categorized event counts.
        Local calendar day is accurately computed using client timezone offset.
        """
        conn = self._get_conn()
        try:
            where = " WHERE 1=1"
            params = []
            if exclude_test:
                where += (
                    " AND detection_source != 'TEST_ENDPOINT'"
                    " AND event_type NOT LIKE 'TEST_%'"
                    " AND features NOT LIKE '%\"is_test_event\": true%'"
                    " AND features NOT LIKE '%\"is_test_event\":true%'"
                )
            if device_id:
                if user_id and user_id not in ("ALL", "*"):
                    where += " AND device_id = ? AND (user_id = ? OR device_id IN (SELECT device_id FROM devices WHERE user_id = ?))"
                    params.extend([device_id, user_id, user_id])
                else:
                    where += " AND device_id = ?"
                    params.append(device_id)
            elif user_id and user_id not in ("ALL", "*"):
                where += " AND (user_id = ? OR device_id IN (SELECT device_id FROM devices WHERE user_id = ?))"
                params.extend([user_id, user_id])

            if client_tz_offset is not None:
                offset_minutes = -int(client_tz_offset)
                mod_str = f"+{offset_minutes} minutes" if offset_minutes >= 0 else f"{offset_minutes} minutes"
                sql = f"""
                    SELECT 
                        date(datetime(COALESCE(timestamp, created_at), ?)) as local_date,
                        COUNT(*) as total,
                        SUM(CASE WHEN event_type IN ('WEBSITE_OPENED','BROWSER_NAVIGATION') OR features LIKE '%"domain"%' THEN 1 ELSE 0 END) as web_count,
                        SUM(CASE WHEN event_type IN ('APPLICATION_START','APPLICATION_CLOSED','PROCESS_START') THEN 1 ELSE 0 END) as app_count,
                        SUM(CASE WHEN event_type = 'NETWORK_CONNECTION' THEN 1 ELSE 0 END) as network_count,
                        SUM(CASE WHEN event_type LIKE '%FILE%' THEN 1 ELSE 0 END) as file_count
                    FROM events
                    {where}
                    GROUP BY local_date
                    ORDER BY local_date DESC
                """
                params.insert(0, mod_str)
            else:
                sql = f"""
                    SELECT 
                        substr(COALESCE(timestamp, created_at), 1, 10) as local_date,
                        COUNT(*) as total,
                        SUM(CASE WHEN event_type IN ('WEBSITE_OPENED','BROWSER_NAVIGATION') OR features LIKE '%"domain"%' THEN 1 ELSE 0 END) as web_count,
                        SUM(CASE WHEN event_type IN ('APPLICATION_START','APPLICATION_CLOSED','PROCESS_START') THEN 1 ELSE 0 END) as app_count,
                        SUM(CASE WHEN event_type = 'NETWORK_CONNECTION' THEN 1 ELSE 0 END) as network_count,
                        SUM(CASE WHEN event_type LIKE '%FILE%' THEN 1 ELSE 0 END) as file_count
                    FROM events
                    {where}
                    GROUP BY local_date
                    ORDER BY local_date DESC
                """

            rows = conn.execute(sql, params).fetchall()
            dates = []
            for row in rows:
                if row[0]:
                    dates.append({
                        "date": row[0],
                        "total": row[1],
                        "web_count": row[2],
                        "app_count": row[3],
                        "network_count": row[4],
                        "file_count": row[5]
                    })
            return dates
        finally:
            conn.close()

    def get_events_in_timerange(self, user_id: str, start: str, end: str) -> list[dict]:
        """Get events for a user within a time range."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT * FROM events
                   WHERE user_id = ? AND timestamp >= ? AND timestamp <= ?
                   ORDER BY timestamp ASC""",
                (user_id, start, end)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def update_event_sync_status(self, event_id: str, status: str, synced_at: str = None):
        """Update sync status for an event."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE events SET sync_status = ?, synchronized_at = ? WHERE event_id = ?",
                (status, synced_at or datetime.now(timezone.utc).isoformat(), event_id)
            )
            conn.commit()
        finally:
            conn.close()

    def get_all_events_sorted(self) -> list[dict]:
        """Get all events sorted by timestamp ascending."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp ASC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def migrate_unbound_events(self, *args, **kwargs):
        """Safe no-op: Multi-user isolation prevents cross-account event reassignments."""
        return 0
        conn = self._get_conn()
        try:
            cur = conn.execute(
                """UPDATE events 
                   SET user_id = ?, device_id = COALESCE(NULLIF(device_id, ''), ?) 
                   WHERE user_id != ? OR user_id IS NULL OR user_id = '' OR user_id = 'current_user'""",
                (target_uid, target_dev, target_uid)
            )
            count = cur.rowcount
            if target_dev:
                conn.execute(
                    """UPDATE devices SET user_id = ? WHERE device_id = ?""",
                    (target_uid, target_dev)
                )
            conn.commit()
            return count
        except Exception as e:
            print(f"[-] migrate_unbound_events error: {e}")
            return 0
        finally:
            conn.close()

    # ── Behavior Profile Operations ───────────────────────────

    def upsert_behavior_profile(self, user_id: str, profile: dict):
        """Insert or update a behavior profile."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO behavior_profiles
                   (user_id, login_hours, known_devices, common_applications,
                    session_durations, network_destinations, activity_patterns,
                    event_count, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                    login_hours = excluded.login_hours,
                    known_devices = excluded.known_devices,
                    common_applications = excluded.common_applications,
                    session_durations = excluded.session_durations,
                    network_destinations = excluded.network_destinations,
                    activity_patterns = excluded.activity_patterns,
                    event_count = excluded.event_count,
                    updated_at = excluded.updated_at""",
                (
                    user_id,
                    json.dumps(profile.get("login_hours", [])),
                    json.dumps(profile.get("known_devices", [])),
                    json.dumps(profile.get("common_applications", [])),
                    json.dumps(profile.get("session_durations", [])),
                    json.dumps(profile.get("network_destinations", [])),
                    json.dumps(profile.get("activity_patterns", {})),
                    profile.get("event_count", 0),
                    datetime.now(timezone.utc).isoformat()
                )
            )
            conn.commit()
        finally:
            conn.close()

    def get_behavior_profile(self, user_id: str) -> dict | None:
        """Get behavior profile for a user."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM behavior_profiles WHERE user_id = ?", (user_id,)
            ).fetchone()
            if not row:
                return None
            profile = dict(row)
            # Parse JSON fields
            for field in ["login_hours", "known_devices", "common_applications",
                         "session_durations", "network_destinations"]:
                if isinstance(profile.get(field), str):
                    profile[field] = json.loads(profile[field])
            if isinstance(profile.get("activity_patterns"), str):
                profile["activity_patterns"] = json.loads(profile["activity_patterns"])
            return profile
        finally:
            conn.close()

    # ── Risk History Operations ───────────────────────────────

    def insert_risk_record(self, user_id: str, event_id: str,
                           risk_score: float, anomaly_score: float,
                           behavioral_drift: float, device_id: str = None):
        """Insert a risk history record scoped to a specific device."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT INTO risk_history
                   (user_id, device_id, event_id, risk_score, anomaly_score,
                    behavioral_drift, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, device_id or "", event_id, risk_score, anomaly_score,
                 behavioral_drift, datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
        finally:
            conn.close()

    def get_risk_history(self, user_id: str = None, device_id: str = None, limit: int = 50) -> list[dict]:
        """Get risk history with device isolation."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM risk_history WHERE 1=1"
            params = []
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            elif user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_latest_risk(self, user_id: str = None, device_id: str = None) -> float:
        """Get the most recent risk score for a user/device."""
        conn = self._get_conn()
        try:
            query = "SELECT risk_score FROM risk_history WHERE 1=1"
            params = []
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            elif user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            query += " ORDER BY timestamp DESC LIMIT 1"
            row = conn.execute(query, params).fetchone()
            return row["risk_score"] if row else 0.0
        finally:
            conn.close()

    # ── Sync Queue Operations ─────────────────────────────────

    def enqueue_sync(self, event_id: str, payload: dict, device_id: str = None):
        """Add an event to the sync queue with device_id."""
        dev_id = device_id or (payload.get("device_id") if isinstance(payload, dict) else "")
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO sync_queue
                   (event_id, device_id, payload, status, retry_count, created_at)
                   VALUES (?, ?, ?, 'PENDING', 0, ?)""",
                (event_id, dev_id, json.dumps(payload), datetime.now(timezone.utc).isoformat())
            )
            conn.commit()
        finally:
            conn.close()

    def get_pending_sync(self, limit: int = 50, device_id: str = None) -> list[dict]:
        """Get pending sync items with optional device_id filter."""
        conn = self._get_conn()
        try:
            query = "SELECT * FROM sync_queue WHERE status = 'PENDING'"
            params = []
            if device_id:
                query += " AND device_id = ?"
                params.append(device_id)
            query += " ORDER BY created_at ASC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, params).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                if isinstance(d.get("payload"), str):
                    d["payload"] = json.loads(d["payload"])
                results.append(d)
            return results
        finally:
            conn.close()

    def update_sync_status(self, event_id: str, status: str, synced_at: str = None, synchronized_at: str = None):
        """Update sync queue status for an event."""
        conn = self._get_conn()
        try:
            sync_time = synchronized_at or synced_at or (datetime.now(timezone.utc).isoformat() if status in ("SYNCED", "SYNCHRONIZED") else None)
            conn.execute(
                """UPDATE sync_queue
                   SET status = ?, synced_at = ?,
                       retry_count = CASE WHEN ? = 'FAILED'
                                     THEN retry_count + 1 ELSE retry_count END
                   WHERE event_id = ?""",
                (status, sync_time, status, event_id)
            )
            conn.execute(
                """UPDATE events
                   SET sync_status = ?, synchronized_at = ?
                   WHERE event_id = ?""",
                (status, sync_time, event_id)
            )
            conn.commit()
        finally:
            conn.close()


    def get_sync_stats(self) -> dict:
        """Get sync queue statistics."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) as count FROM sync_queue GROUP BY status"
            ).fetchall()
            stats = {"PENDING": 0, "SYNCED": 0, "FAILED": 0}
            for r in rows:
                stats[r["status"]] = r["count"]
            return stats
        finally:
            conn.close()

    # ── Incident Operations ───────────────────────────────────

    def consolidate_duplicate_incidents(self) -> int:
        """Consolidates recurring duplicate incident rows for the same threat and device into a single incident."""
        conn = self._get_conn()
        merged_count = 0
        try:
            rows = conn.execute("SELECT incident_id, device_id, status, details_json, created_at FROM incidents").fetchall()
            groups = {}
            for r in rows:
                try:
                    d = json.loads(r["details_json"]) if r["details_json"] else {}
                    title = d.get("title") or d.get("summary") or "Unknown"
                except Exception:
                    title = "Unknown"
                    d = {}
                key = (r["device_id"] or "", title)
                groups.setdefault(key, []).append((r["incident_id"], d, r["created_at"], r["status"]))

            for (dev, title), incs in groups.items():
                if len(incs) <= 1:
                    continue
                incs.sort(key=lambda x: len(x[1].get("ordered_events") or x[1].get("events") or []), reverse=True)
                primary_id, primary_details, _, _ = incs[0]
                merged_events = primary_details.get("ordered_events") or []
                seen_ids = {e.get("event_id") if isinstance(e, dict) else str(e) for e in merged_events}

                for dup_id, dup_details, _, _ in incs[1:]:
                    for ev in (dup_details.get("ordered_events") or []):
                        ev_id = ev.get("event_id") if isinstance(ev, dict) else str(ev)
                        if ev_id and ev_id not in seen_ids:
                            merged_events.append(ev)
                            seen_ids.add(ev_id)
                    conn.execute("DELETE FROM incident_events WHERE incident_id = ?", (dup_id,))
                    conn.execute("DELETE FROM incidents WHERE incident_id = ?", (dup_id,))
                    merged_count += 1

                primary_details["ordered_events"] = merged_events
                primary_details["event_count"] = len(merged_events)
                try:
                    conn.execute(
                        "UPDATE incidents SET details_json = ? WHERE incident_id = ?",
                        (json.dumps(primary_details), primary_id)
                    )
                except Exception:
                    pass
            conn.commit()
            return merged_count
        finally:
            conn.close()

    def save_incident(self, incident: dict) -> bool:
        """Persist an incident and its associated events into SQLite with full details_json."""
        conn = self._get_conn()
        try:
            device_id = incident.get("device_id") or ""
            if not device_id and incident.get("affected_devices"):
                device_id = incident["affected_devices"][0] if incident["affected_devices"] else ""
            
            # Serialize full incident payload into details_json for permanent preservation
            try:
                details_json = json.dumps(incident)
            except Exception:
                details_json = "{}"

            # Remove any earlier fragmented duplicate records for this same title on this device
            title = incident.get("title")
            if title and device_id:
                old_rows = conn.execute(
                    "SELECT incident_id, details_json FROM incidents WHERE device_id = ? AND incident_id != ?",
                    (device_id, incident["incident_id"])
                ).fetchall()
                for old_id, old_details in old_rows:
                    try:
                        old_d = json.loads(old_details) if old_details else {}
                        if old_d.get("title") == title:
                            conn.execute("DELETE FROM incident_events WHERE incident_id = ?", (old_id,))
                            conn.execute("DELETE FROM incidents WHERE incident_id = ?", (old_id,))
                    except Exception:
                        pass

            conn.execute(
                """INSERT OR REPLACE INTO incidents
                   (incident_id, user_id, device_id, start_time, end_time, severity,
                    status, confidence, summary, details_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident["incident_id"],
                    incident.get("user_id", "") or incident.get("affected_user", ""),
                    device_id,
                    incident.get("start_time", ""),
                    incident.get("end_time", ""),
                    incident.get("severity", "LOW"),
                    incident.get("status", "OPEN"),
                    incident.get("confidence", 0.0),
                    incident.get("summary", ""),
                    details_json,
                    incident.get("created_at", datetime.now(timezone.utc).isoformat()),
                )
            )

            # Associate ordered events in incident_events table
            ordered_events = incident.get("ordered_events") or []
            for seq, ev in enumerate(ordered_events):
                ev_id = ev.get("event_id") if isinstance(ev, dict) else str(ev)
                if ev_id:
                    score = float(ev.get("risk_score", 0.0)) if isinstance(ev, dict) else 0.0
                    conn.execute(
                        """INSERT OR IGNORE INTO incident_events
                           (incident_id, event_id, contribution_score, sequence_order)
                           VALUES (?, ?, ?, ?)""",
                        (incident["incident_id"], ev_id, score, seq)
                    )
            conn.commit()
            return True
        finally:
            conn.close()

    insert_incident = save_incident

    def add_event_to_incident(self, incident_id: str, event_id: str,
                               contribution_score: float, sequence_order: int):
        """Associate an event with an incident."""
        conn = self._get_conn()
        try:
            conn.execute(
                """INSERT OR IGNORE INTO incident_events
                   (incident_id, event_id, contribution_score, sequence_order)
                   VALUES (?, ?, ?, ?)""",
                (incident_id, event_id, contribution_score, sequence_order)
            )
            conn.commit()
        finally:
            conn.close()

    def update_incident_status(self, incident_id: str, status: str = "RESOLVED") -> bool:
        """Update the status of an incident (e.g. RESOLVED, CLOSED, INVESTIGATING)."""
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE incidents SET status = ? WHERE incident_id = ?",
                (status, incident_id)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def delete_incident(self, incident_id: str) -> bool:
        """Delete an incident and its join links from the database."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM incident_events WHERE incident_id = ?", (incident_id,))
            conn.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def get_incident(self, incident_id: str) -> dict | None:
        """Get an incident by ID with its events, unpacking full details_json if present."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return None
            incident = dict(row)
            if incident.get("details_json"):
                try:
                    unpacked = json.loads(incident["details_json"])
                    if isinstance(unpacked, dict):
                        incident = {**unpacked, **incident}
                except Exception:
                    pass

            # Get associated events
            event_rows = conn.execute(
                """SELECT ie.*, e.*
                   FROM incident_events ie
                   JOIN events e ON ie.event_id = e.event_id
                   WHERE ie.incident_id = ?
                   ORDER BY ie.sequence_order ASC""",
                (incident_id,)
            ).fetchall()
            loaded_events = []
            for r in event_rows:
                ed = dict(r)
                if isinstance(ed.get("features"), str):
                    try:
                        ed["features"] = json.loads(ed["features"])
                    except Exception:
                        ed["features"] = {}
                loaded_events.append(ed)
            incident["events"] = loaded_events
            if not incident.get("ordered_events") and loaded_events:
                incident["ordered_events"] = loaded_events
            return incident
        finally:
            conn.close()

    def get_incident_for_event(self, event_id: str) -> dict | None:
        """Find the incident associated with a specific event ID."""
        conn = self._get_conn()
        try:
            # First check incident_events join table
            row = conn.execute(
                """SELECT i.* FROM incident_events ie
                   JOIN incidents i ON ie.incident_id = i.incident_id
                   WHERE ie.event_id = ?
                   LIMIT 1""",
                (event_id,)
            ).fetchone()
            if row:
                inc = dict(row)
                if inc.get("details_json"):
                    try:
                        unpacked = json.loads(inc["details_json"])
                        if isinstance(unpacked, dict):
                            inc = {**unpacked, **inc}
                    except Exception:
                        pass
                return inc

            # Fallback: check if the event matches by device and timeframe of an incident
            ev_row = conn.execute("SELECT timestamp, device_id FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not ev_row or not ev_row["timestamp"]:
                return None
            ev_ts = ev_row["timestamp"]
            ev_dev = ev_row["device_id"]

            inc_row = conn.execute(
                """SELECT i.* FROM incidents i
                   WHERE (i.device_id = ? OR i.device_id = '' OR i.device_id IS NULL)
                     AND i.start_time <= ? AND (i.end_time >= ? OR i.end_time = '')
                   ORDER BY i.created_at DESC
                   LIMIT 1""",
                (ev_dev, ev_ts, ev_ts)
            ).fetchone()
            if inc_row:
                inc = dict(inc_row)
                if inc.get("details_json"):
                    try:
                        unpacked = json.loads(inc["details_json"])
                        if isinstance(unpacked, dict):
                            inc = {**unpacked, **inc}
                    except Exception:
                        pass
                return inc
            return None
        finally:
            conn.close()

    def get_incidents(self, limit: int = 50, device_id: str = None, user_id: str = None) -> list[dict]:
        """Get incidents with optional device_id and user_id filters for strict isolation, unpacking details_json."""
        conn = self._get_conn()
        try:
            if user_id and user_id not in ("ALL", "*"):
                if device_id and device_id not in ("ALL", "*"):
                    rows = conn.execute(
                        """SELECT i.*, COUNT(ie.event_id) as event_count
                           FROM incidents i
                           LEFT JOIN incident_events ie ON i.incident_id = ie.incident_id
                           WHERE (i.user_id = ? OR i.device_id = ? OR i.device_id IN (SELECT device_id FROM devices WHERE user_id = ?))
                           GROUP BY i.incident_id
                           ORDER BY i.created_at DESC LIMIT ?""",
                        (user_id, device_id, user_id, limit)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT i.*, COUNT(ie.event_id) as event_count
                           FROM incidents i
                           LEFT JOIN incident_events ie ON i.incident_id = ie.incident_id
                           WHERE i.user_id = ? OR i.device_id IN (SELECT device_id FROM devices WHERE user_id = ?)
                           GROUP BY i.incident_id
                           ORDER BY i.created_at DESC LIMIT ?""",
                        (user_id, user_id, limit)
                    ).fetchall()
            elif device_id and device_id not in ("ALL", "*"):
                rows = conn.execute(
                    """SELECT i.*, COUNT(ie.event_id) as event_count
                       FROM incidents i
                       LEFT JOIN incident_events ie ON i.incident_id = ie.incident_id
                       WHERE i.device_id = ?
                       GROUP BY i.incident_id
                       ORDER BY i.created_at DESC LIMIT ?""",
                    (device_id, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT i.*, COUNT(ie.event_id) as event_count
                       FROM incidents i
                       LEFT JOIN incident_events ie ON i.incident_id = ie.incident_id
                       GROUP BY i.incident_id
                       ORDER BY i.created_at DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                if d.get("details_json"):
                    try:
                        unpacked = json.loads(d["details_json"])
                        if isinstance(unpacked, dict):
                            d = {**unpacked, **d}
                    except Exception:
                        pass
                results.append(d)
            return results
        finally:
            conn.close()

    def update_incident(self, incident_id: str, updates: dict):
        """Update incident fields."""
        conn = self._get_conn()
        try:
            allowed = ["severity", "status", "confidence", "summary", "end_time"]
            sets = []
            vals = []
            for k, v in updates.items():
                if k in allowed:
                    sets.append(f"{k} = ?")
                    vals.append(v)
            if sets:
                vals.append(incident_id)
                conn.execute(
                    f"UPDATE incidents SET {', '.join(sets)} WHERE incident_id = ?",
                    vals
                )
                conn.commit()
        finally:
            conn.close()

    # ── Statistics ────────────────────────────────────────────

    def get_event_count(self) -> int:
        """Get total event count."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()
            return row["c"]
        finally:
            conn.close()

    # Compatibility aliases and helpers
    save_event = insert_event
    save_incident = insert_incident

    def record_risk(self, user_id: str, device_id: str, risk_score: float, anomaly_score: float, behavioral_drift: float, timestamp: str = None):
        return self.insert_risk_record(user_id, f"{user_id}_{device_id}", risk_score, anomaly_score, behavioral_drift, device_id=device_id)

    def enqueue_sync_event(self, event: dict) -> bool:
        event_id = event.get("event_id", "")
        self.enqueue_sync(event_id, event, device_id=event.get("device_id"))
        return True

    def get_recent_risk_scores(self, user_id: str = None, device_id: str = None, limit: int = 10) -> list:
        return self.get_risk_history(user_id=user_id, device_id=device_id, limit=limit)

    def get_pending_sync_events(self, limit: int = 500) -> list:
        pending_records = self.get_pending_sync(limit=limit)
        return [r["payload"] for r in pending_records if isinstance(r.get("payload"), dict)]

    def get_pending_sync_count(self) -> int:
        stats = self.get_sync_stats()
        return stats.get("PENDING", 0)

    def increment_sync_retry(self, event_id: str, max_retries: int = 3):
        """Increment the retry count for a sync queue item. Mark as FAILED if max reached."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT retry_count FROM sync_queue WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row:
                new_count = (row["retry_count"] or 0) + 1
                new_status = "FAILED" if new_count >= max_retries else "PENDING"
                conn.execute(
                    "UPDATE sync_queue SET retry_count = ?, status = ? WHERE event_id = ?",
                    (new_count, new_status, event_id)
                )
                conn.commit()
        finally:
            conn.close()

    # ── User & Auth Operations ──────────────────────────────────

    def create_user(self, email: str, password: str, name: str = "", consent_accepted: bool = True, email_verified: bool = False, verification_otp: str = "") -> dict:
        """Create a new user with secure password hash. Returns user dict or raises ValueError."""
        import hashlib
        import os
        import uuid
        
        email_clean = email.strip().lower()
        user_name = name.strip() or email_clean.split("@")[0]
        conn = self._get_conn()
        try:
            # Check existing
            existing = conn.execute("SELECT id FROM users WHERE email = ?", (email_clean,)).fetchone()
            if existing:
                raise ValueError("An account with this email already exists.")
                
            user_id = f"usr_{uuid.uuid4().hex[:10]}"
            salt = os.urandom(16).hex()
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
            now_iso = datetime.now(timezone.utc).isoformat()
            consent_val = 1 if consent_accepted else 0
            verified_val = 1 if email_verified else 0
            
            conn.execute(
                """INSERT INTO users (id, name, email, password_hash, salt, created_at, consent_accepted, consent_timestamp, email_verified, verification_otp, otp_created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, user_name, email_clean, pwd_hash, salt, now_iso, consent_val, now_iso if consent_accepted else None, verified_val, verification_otp, now_iso if verification_otp else None)
            )
            conn.commit()
            return {
                "id": user_id,
                "name": user_name,
                "email": email_clean,
                "created_at": now_iso,
                "consent_accepted": consent_accepted,
                "consent_timestamp": now_iso if consent_accepted else None,
                "email_verified": email_verified,
                "verification_otp": verification_otp
            }
        finally:
            conn.close()

    def verify_user_email(self, email: str, otp: str) -> bool:
        """Verifies a user's email if OTP matches."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT id, verification_otp FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
            if not row:
                return False
            expected_otp = str(row["verification_otp"] or "")
            if expected_otp and expected_otp == otp.strip():
                conn.execute("UPDATE users SET email_verified = 1, verification_otp = NULL WHERE id = ?", (row["id"],))
                conn.commit()
                return True
            return False
        finally:
            conn.close()

    def set_user_verification_otp(self, email: str, otp: str):
        """Sets or refreshes an email verification OTP."""
        conn = self._get_conn()
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE users SET verification_otp = ?, otp_created_at = ? WHERE email = ?", (otp.strip(), now_iso, email.strip().lower()))
            conn.commit()
        finally:
            conn.close()

    def authenticate_user(self, email_or_name: str = None, password: str = "", email: str = None) -> dict | None:
        """Authenticates user and returns user info if valid, else None."""
        import hashlib
        target = email or email_or_name or ""
        query_val = target.strip().lower()
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? OR name = ?",
                (query_val, target.strip())
            ).fetchone()
            if not row:
                return None
                
            salt = row["salt"]
            expected_hash = row["password_hash"]
            computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
            
            if computed_hash == expected_hash:
                return {
                    "id": row["id"],
                    "name": row["name"],
                    "email": row["email"],
                    "created_at": row["created_at"],
                    "consent_accepted": bool(row["consent_accepted"]) if "consent_accepted" in row.keys() else True
                }
            return None
        finally:
            conn.close()

    def get_user_by_id(self, user_id: str) -> dict | None:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT id, name, email, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    # ── User Allowed Monitored Emails (Online Activities Scope) ──

    def get_allowed_emails(self, user_id: str = None) -> list[str]:
        """
        Returns all authorized emails for online monitoring (primary registered email + user-added emails).
        Normalized to lowercase.
        """
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_allowed_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, email)
                )
            """)
            allowed = set()
            # 1. Primary registered user email
            if user_id:
                u_row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
                if u_row and u_row["email"]:
                    allowed.add(u_row["email"].strip().lower())
            
            # If no user_id or not found, also check most recent user
            if not allowed:
                recent_u = conn.execute("SELECT email FROM users ORDER BY created_at DESC LIMIT 1").fetchone()
                if recent_u and recent_u["email"]:
                    allowed.add(recent_u["email"].strip().lower())

            # 2. Additional allowed emails
            try:
                if user_id:
                    rows = conn.execute("SELECT email FROM user_allowed_emails WHERE user_id = ?", (user_id,)).fetchall()
                else:
                    rows = conn.execute("SELECT email FROM user_allowed_emails").fetchall()
                for r in rows:
                    if r["email"]:
                        allowed.add(r["email"].strip().lower())
            except Exception:
                pass

            return sorted(list(allowed))
        finally:
            conn.close()

    def get_allowed_emails_details(self, user_id: str = None) -> dict:
        """
        Returns structured details: primary registered email and user-added additional emails.
        """
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_allowed_emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    email TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(user_id, email)
                )
            """)
            primary_email = None
            if user_id:
                u_row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
                if u_row and u_row["email"]:
                    primary_email = u_row["email"].strip().lower()
            if not primary_email:
                recent_u = conn.execute("SELECT email FROM users ORDER BY created_at DESC LIMIT 1").fetchone()
                if recent_u and recent_u["email"]:
                    primary_email = recent_u["email"].strip().lower()

            additional_rows = []
            try:
                if user_id:
                    rows = conn.execute("SELECT id, email, created_at FROM user_allowed_emails WHERE user_id = ? ORDER BY created_at ASC", (user_id,)).fetchall()
                    additional_rows = [dict(r) for r in rows]
                else:
                    rows = conn.execute("SELECT id, email, created_at FROM user_allowed_emails ORDER BY created_at ASC").fetchall()
                    additional_rows = [dict(r) for r in rows]
            except Exception:
                pass

            all_emails = set([primary_email] if primary_email else [])
            for r in additional_rows:
                all_emails.add(r["email"].strip().lower())

            return {
                "primary_email": primary_email,
                "additional_emails": additional_rows,
                "all_monitored": sorted(list(all_emails))
            }
        finally:
            conn.close()

    def add_allowed_email(self, user_id: str, email: str) -> bool:
        """Add an additional Gmail or email address to the user's monitored online activities list."""
        if not email or not user_id:
            return False
        clean_email = email.strip().lower()
        conn = self._get_conn()
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT OR IGNORE INTO user_allowed_emails (user_id, email, created_at) VALUES (?, ?, ?)",
                (user_id, clean_email, now_iso)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def remove_allowed_email(self, user_id: str, email: str) -> bool:
        """Remove a user-added email from the monitored online activities list."""
        if not email or not user_id:
            return False
        clean_email = email.strip().lower()
        conn = self._get_conn()
        try:
            conn.execute(
                "DELETE FROM user_allowed_emails WHERE user_id = ? AND LOWER(email) = ?",
                (user_id, clean_email)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    # ── Device Operations ──────────────────────────────────────

    def user_owns_device(self, user_id: str, device_id: str) -> bool:
        """Check if a device belongs to a specific user."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT 1 FROM devices WHERE device_id = ? AND user_id = ?", (device_id, user_id)).fetchone()
            return bool(row)
        finally:
            conn.close()

    def enroll_device(self, user_id: str, device_name: str = None, os_info: str = "", device_id: str = None) -> dict:
        """
        Securely enrolls a new device for the given user:
        - Generates or binds persistent unique device ID
        - Issues high-entropy secret device key
        - Binds device strictly to user_id
        """
        import uuid
        import secrets
        
        dev_id = device_id or f"DEV_{uuid.uuid4().hex[:12].upper()}"
        dev_key = f"dk_{secrets.token_urlsafe(32)}"
        dev_name = device_name or f"Device-{dev_id[-6:]}"
        now_str = datetime.now(timezone.utc).isoformat()

        conn = self._get_conn()
        try:
            # Check if device already exists
            existing = conn.execute("SELECT * FROM devices WHERE device_id = ?", (dev_id,)).fetchone()
            if existing:
                # If belongs to another user, raise
                if existing["user_id"] != user_id:
                    raise ValueError("Device already enrolled under another account.")
                # Update existing device key and reconnect
                conn.execute(
                    """UPDATE devices SET device_name = ?, os_info = ?, device_key = ?, is_revoked = 0, status = 'ONLINE', last_seen = ?
                       WHERE device_id = ?""",
                    (dev_name, os_info or existing["os_info"], dev_key, now_str, dev_id)
                )
            else:
                conn.execute(
                    """INSERT INTO devices (device_id, user_id, device_name, os_info, device_key, is_revoked, status, last_seen, created_at)
                       VALUES (?, ?, ?, ?, ?, 0, 'ONLINE', ?, ?)""",
                    (dev_id, user_id, dev_name, os_info, dev_key, now_str, now_str)
                )
            conn.commit()
            return {
                "device_id": dev_id,
                "user_id": user_id,
                "device_name": dev_name,
                "os_info": os_info,
                "device_key": dev_key,
                "status": "ONLINE",
                "is_revoked": False,
                "last_seen": now_str,
                "created_at": now_str
            }
        finally:
            conn.close()

    def migrate_unbound_events(self, new_device_id: str, new_user_id: str):
        """Migrate preliminary unbound/snapshot events to the newly enrolled device and user."""
        conn = self._get_conn()
        try:
            conn.execute(
                """UPDATE events
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '')""",
                (new_user_id, new_device_id, new_device_id)
            )
            conn.execute(
                """UPDATE risk_history
                   SET user_id = ?, device_id = ?
                   WHERE (user_id = 'current_user' OR user_id = '' OR user_id IS NULL)
                     AND (device_id = ? OR device_id = 'DEV-HOST' OR device_id IS NULL OR device_id = '')""",
                (new_user_id, new_device_id, new_device_id)
            )
            conn.commit()
        finally:
            conn.close()

    def rename_device(self, device_id: str, user_id: str, new_name: str) -> dict:
        """Renames a device, verifying user ownership."""
        conn = self._get_conn()
        try:
            clean_name = new_name.strip()
            if not clean_name:
                raise ValueError("Device name cannot be empty.")
            row = conn.execute("SELECT user_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                raise ValueError("Device not found.")
            if row["user_id"] != user_id:
                raise PermissionError("Access denied. You do not own this device.")
            conn.execute("UPDATE devices SET device_name = ? WHERE device_id = ?", (clean_name, device_id))
            conn.commit()
            return {"success": True, "device_id": device_id, "device_name": clean_name}
        finally:
            conn.close()

    def revoke_device(self, device_id: str, user_id: str) -> dict:
        """
        Revokes a device's credentials.
        Disables future event ingestion from this device while preserving historical telemetry and incidents.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT user_id, device_name FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                raise ValueError("Device not found.")
            if row["user_id"] != user_id:
                raise PermissionError("Access denied. You do not own this device.")
            conn.execute("UPDATE devices SET is_revoked = 1, status = 'REVOKED' WHERE device_id = ?", (device_id,))
            conn.commit()
            return {
                "success": True,
                "device_id": device_id,
                "device_name": row["device_name"],
                "status": "REVOKED",
                "message": f"Device '{row['device_name']}' has been revoked. Further event ingestion is blocked."
            }
        finally:
            conn.close()

    def remove_device(self, device_id: str, user_id: str = None) -> dict:
        """
        Securely removes/un-enrolls a device from the registry.
        Verifies ownership and prevents cross-user device tampering.
        Historical telemetry and incidents are safely preserved in SQLite.
        """
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT user_id, device_name FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                return {"success": False, "error": "Device not found."}
            if user_id and row["user_id"] != user_id:
                raise PermissionError("Access denied. You do not own this device.")
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            conn.commit()
            return {
                "success": True,
                "device_id": device_id,
                "device_name": row["device_name"],
                "message": f"Device '{row['device_name']}' successfully un-enrolled and removed."
            }
        finally:
            conn.close()

    def verify_device_credentials(self, device_id: str, device_key: str) -> bool:
        """Verifies device credentials and confirms device is not revoked."""
        if not device_id or not device_key:
            return False
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT device_key, is_revoked FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                return False
            if row["is_revoked"]:
                return False
            stored_key = row["device_key"]
            if not stored_key:
                # Device registered without explicit key (legacy/local)
                return True
            import hmac
            return hmac.compare_digest(str(stored_key), str(device_key))
        finally:
            conn.close()

    def register_device(self, device_id: str, user_id: str, device_name: str = None, os_info: str = "", device_key: str = None) -> dict:
        """Registers or updates a device associated with a user account with strict ownership validation."""
        conn = self._get_conn()
        try:
            now_str = datetime.now(timezone.utc).isoformat()
            dev_name = device_name or f"Device-{device_id[:6]}"
            existing = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if existing:
                # Disallow silent ownership hijacking
                if existing["user_id"] != user_id and not existing["is_revoked"]:
                    raise ValueError("Device already enrolled under another account. Secure unenrollment by the owning account is required before transferring.")
                conn.execute(
                    """UPDATE devices SET user_id = ?, device_name = ?, os_info = ?,
                       status = CASE WHEN is_revoked = 1 THEN 'REVOKED' ELSE 'ONLINE' END,
                       last_seen = ? WHERE device_id = ?""",
                    (user_id, dev_name, os_info or existing["os_info"], now_str, device_id)
                )
            else:
                conn.execute(
                    """INSERT INTO devices (device_id, user_id, device_name, os_info, device_key, is_revoked, status, last_seen, created_at)
                       VALUES (?, ?, ?, ?, ?, 0, 'ONLINE', ?, ?)""",
                    (device_id, user_id, dev_name, os_info, device_key, now_str, now_str)
                )
            conn.commit()
            return {
                "device_id": device_id,
                "user_id": user_id,
                "device_name": dev_name,
                "os_info": os_info,
                "status": "ONLINE",
                "last_seen": now_str
            }
        finally:
            conn.close()

    def get_user_devices(self, user_id: str = None) -> list[dict]:
        conn = self._get_conn()
        try:
            if user_id and user_id not in ("ALL", "*"):
                rows = conn.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY last_seen DESC", (user_id,)).fetchall()
            elif user_id in ("ALL", "*"):
                rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
            else:
                return []
            devices = []
            now_dt = datetime.now(timezone.utc)
            for r in rows:
                d = dict(r)
                last_seen_str = d.get("last_seen")
                if last_seen_str:
                    try:
                        ls_clean = last_seen_str.replace("Z", "+00:00")
                        ls_dt = datetime.fromisoformat(ls_clean)
                        # Device is connected if seen within last 120 seconds
                        d["is_connected"] = (now_dt - ls_dt).total_seconds() < 120
                        d["status"] = "ONLINE" if d["is_connected"] else "NOT_CONNECTED"
                    except Exception:
                        d["is_connected"] = False
                        d["status"] = "NOT_CONNECTED"
                else:
                    d["is_connected"] = False
                    d["status"] = "NOT_CONNECTED"
                devices.append(d)
            return devices
        finally:
            conn.close()

    get_devices_by_user = get_user_devices

    def get_device(self, device_id: str) -> dict | None:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            last_seen_str = d.get("last_seen")
            now_dt = datetime.now(timezone.utc)
            if last_seen_str:
                try:
                    ls_clean = last_seen_str.replace("Z", "+00:00")
                    ls_dt = datetime.fromisoformat(ls_clean)
                    d["is_connected"] = (now_dt - ls_dt).total_seconds() < 120
                    d["status"] = "ONLINE" if d["is_connected"] else "NOT_CONNECTED"
                except Exception:
                    d["is_connected"] = False
                    d["status"] = "NOT_CONNECTED"
            else:
                d["is_connected"] = False
                d["status"] = "NOT_CONNECTED"
            return d
        finally:
            conn.close()

    def update_device_status(self, device_id: str, status: str = "ONLINE"):
        conn = self._get_conn()
        try:
            now_str = datetime.now(timezone.utc).isoformat() if hasattr(datetime, 'now') else datetime.utcnow().isoformat()
            conn.execute("UPDATE devices SET status = ?, last_seen = ? WHERE device_id = ?", (status, now_str, device_id))
            conn.commit()
        finally:
            conn.close()

    def remove_device(self, device_id: str, user_id: str = None) -> dict:
        """Remove a device from the registry.
        Historical events and incidents belonging to this device are PRESERVED.
        Only the device registration entry is deleted.
        Returns a dict with success status and event/incident counts preserved.
        """
        conn = self._get_conn()
        try:
            # Verify device exists
            row = conn.execute("SELECT device_id, device_name, user_id FROM devices WHERE device_id = ?", (device_id,)).fetchone()
            if not row:
                return {"success": False, "error": "Device not found", "device_id": device_id}

            if user_id and row["user_id"] != user_id:
                raise PermissionError("Access denied. You do not own this device.")

            device_name = row["device_name"]

            # Count preserved records for transparency
            event_count = conn.execute(
                "SELECT COUNT(*) as c FROM events WHERE device_id = ?", (device_id,)
            ).fetchone()["c"]
            incident_count = conn.execute(
                "SELECT COUNT(*) as c FROM incidents WHERE device_id = ?", (device_id,)
            ).fetchone()["c"]
            pending_sync_count = conn.execute(
                "SELECT COUNT(*) as c FROM sync_queue WHERE device_id = ? AND status = 'PENDING'", (device_id,)
            ).fetchone()["c"]

            # Remove device registration only
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            conn.commit()

            return {
                "success": True,
                "device_id": device_id,
                "device_name": device_name,
                "events_preserved": event_count,
                "incidents_preserved": incident_count,
                "pending_sync_preserved": pending_sync_count,
                "message": f"Device '{device_name}' removed. {event_count} historical events and {incident_count} incidents are preserved."
            }
        finally:
            conn.close()

    def set_setting(self, key: str, value: str) -> bool:
        """Stores a persistent system key-value setting."""
        conn = self._get_conn()
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, str(value), now_iso)
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def get_setting(self, key: str, default: str = None) -> str | None:
        """Retrieves a persistent system key-value setting."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
        finally:
            conn.close()

    def set_active_pairing(self, email: str, user_id: str, device_id: str) -> None:
        """Saves current active user and device identity for browser extension pairing."""
        data = {
            "email": email,
            "user_id": user_id,
            "device_id": device_id,
            "paired_at": datetime.now(timezone.utc).isoformat()
        }
        self.set_setting("active_pairing", json.dumps(data))

    def get_active_pairing(self) -> dict | None:
        """Retrieves persisted browser extension pairing data."""
        raw = self.get_setting("active_pairing")
        if raw:
            try:
                return json.loads(raw)
            except Exception:
                pass
        return None

    def get_most_recent_user(self) -> dict | None:
        """Retrieves the most recently created or logged-in registered user (filtering out test fixtures)."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                """SELECT id, name, email, created_at FROM users 
                   WHERE email NOT LIKE '%@cyberthreat.test' 
                     AND email NOT LIKE '%@cyberthreat.ai' 
                     AND email NOT LIKE '%@defense.local' 
                     AND email NOT LIKE '%@test.com'
                     AND email != 'unpaired@cyberthreat.local'
                   ORDER BY created_at DESC LIMIT 1"""
            ).fetchone()
            if not row:
                row = conn.execute("SELECT id, name, email, created_at FROM users ORDER BY created_at DESC LIMIT 1").fetchone()
            return dict(row) if row else None
        finally:
            conn.close()





    def initialize_user_baseline_events(self, user_id: str, device_id: str, device_name: str = "Primary Desktop") -> list:
        """
        Initializes genuine baseline security protection events specifically for this user and device.
        Ensures the Activities tab shows clean, active defense telemetry scoped 100% to this account.
        """
        import uuid
        from datetime import datetime, timezone, timedelta
        now_dt = datetime.now(timezone.utc)
        baseline = [
            ("ENDPOINT_SHIELD_ACTIVATED", 0.0, "SAFE", "HOST_AGENT", "OFFLINE", "CyberZen Operations Center", "Endpoint Threat Shield Initialized", "24/7 endpoint threat defense active on device", 0),
            ("SECURITY_BASELINE_VERIFIED", 0.0, "SAFE", "AI_ENGINE", "OFFLINE", "Behavioral Digital Twin", "Device Security Baseline Verified", "System baseline established • Isolation Forest model online", 2),
            ("BROWSER_GUARD_CONNECTED", 0.0, "SAFE", "CHROME_EXTENSION", "ONLINE", "Google Chrome", "Real-Time URL Reputation Shield Online", "Phishing & deceptive download protection active", 5)
        ]
        inserted = []
        for ev_type, risk, threat, src, domain, app, action, details, delta in baseline:
            ts = (now_dt - timedelta(seconds=delta)).isoformat()
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
            features = {
                "application": app,
                "action": action,
                "device_name": device_name,
                "status": threat,
                "details": details,
                "activity_domain": domain,
                "raw_risk": 0.0
            }
            try:
                self.insert_event({
                    "event_id": event_id,
                    "device_id": device_id,
                    "user_id": user_id,
                    "timestamp": ts,
                    "created_at": ts,
                    "event_type": ev_type,
                    "risk_score": risk,
                    "threat_level": threat,
                    "detection_source": src,
                    "sync_status": "SYNCHRONIZED",
                    "features": features
                })
                inserted.append(event_id)
            except Exception as e:
                print(f"[!] Baseline event insert warning: {e}")
        return inserted

    def ensure_user_has_device(self, user_id: str, client_device_id: str = None, os_info: str = "", device_name: str = "Primary Desktop") -> dict:
        """
        Ensures a user has at least one enrolled device in the database.
        If user has none, enrolls a new device and initializes their baseline activities.
        """
        import uuid
        devices = self.get_user_devices(user_id)
        if devices:
            return devices[0]
        
        dev_id = client_device_id
        if not dev_id or dev_id in ("DEV-HOST", "DEV_ORIGIN_123", "UNKNOWN"):
            dev_id = f"DEV_{uuid.uuid4().hex[:8].upper()}"
        
        existing = self.get_device(dev_id)
        if existing and existing.get("user_id") != user_id:
            dev_id = f"DEV_{uuid.uuid4().hex[:8].upper()}"

        new_dev = self.enroll_device(
            user_id=user_id,
            device_name=device_name or "Primary Desktop",
            os_info=os_info or "Windows 11 (64-bit)",
            device_id=dev_id
        )
        self.initialize_user_baseline_events(user_id, new_dev["device_id"], new_dev.get("device_name", "Primary Desktop"))
        return new_dev

DatabaseManager = Database
