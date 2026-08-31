"""
SQLite storage for sessions, events, evidence, scores, and actions.
"""

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'End User',
    created_at REAL NOT NULL,
    last_login_at REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operator_id INTEGER,
    started_at REAL NOT NULL,
    ended_at REAL,
    network_ssid TEXT,
    network_context TEXT,          -- trusted / public-untrusted / unknown
    interface TEXT,
    source TEXT,                   -- 'live' or pcap filename
    FOREIGN KEY(operator_id) REFERENCES operators(id)
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    ts REAL NOT NULL,
    detection_type TEXT NOT NULL,  -- arp_spoof / port_scan / traffic_anomaly / gateway_change
    source_ip TEXT,
    target TEXT,
    severity TEXT NOT NULL,        -- low / medium / high / critical
    confidence REAL NOT NULL,      -- 0.0 - 1.0
    risk_score INTEGER NOT NULL,   -- 0 - 100
    evidence_json TEXT NOT NULL,
    recommended_action TEXT,
    status TEXT NOT NULL DEFAULT 'NEW',  -- NEW / ACK / REVIEW / DISMISSED
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    event_id INTEGER,
    ts REAL NOT NULL,
    action TEXT NOT NULL,          -- seal / unseal / dismiss
    target TEXT,
    confirmed_by_user INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id),
    FOREIGN KEY(event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    abuse_confidence_score INTEGER,
    country TEXT,
    asn TEXT,
    isp TEXT,
    raw_json TEXT
);

CREATE TABLE IF NOT EXISTS operator_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def cursor(self):
        conn = self._connect()
        try:
            cur = conn.cursor()
            yield cur
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    # ---- operators ----
    def has_operators(self) -> bool:
        with self.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM operators")
            return cur.fetchone()["cnt"] > 0

    def create_operator(self, username: str, email: str, password: str, display_name: str = "", role: str = "End User") -> int | None:
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO operators (username, email, password_hash, display_name, role, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (username, email.strip().lower(), self._hash_password(password), display_name or username, role, time.time()),
            )
            return cur.lastrowid

    def authenticate_operator(self, identifier: str, password: str):
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM operators WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
                (identifier.strip(), identifier.strip()),
            )
            row = cur.fetchone()
            if row and row["password_hash"] == self._hash_password(password):
                cur.execute("UPDATE operators SET last_login_at = ? WHERE id = ?", (time.time(), row["id"]))
                return dict(row)
            return None

    def get_operator(self, identifier: str):
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM operators WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
                (identifier.strip(), identifier.strip()),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_operator_by_username(self, username: str):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM operators WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_operator_by_email(self, email: str):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM operators WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cur.fetchone()
            return dict(row) if row else None

    def update_operator_password(self, username: str, new_password: str) -> bool:
        with self.cursor() as cur:
            cur.execute(
                "UPDATE operators SET password_hash = ? WHERE LOWER(username) = LOWER(?)",
                (self._hash_password(new_password), username.strip()),
            )
            return cur.rowcount > 0

    def update_operator_display_name(self, username: str, display_name: str) -> bool:
        with self.cursor() as cur:
            cur.execute(
                "UPDATE operators SET display_name = ? WHERE LOWER(username) = LOWER(?)",
                (display_name, username.strip()),
            )
            return cur.rowcount > 0

    def list_operators(self) -> list[dict]:
        with self.cursor() as cur:
            cur.execute("SELECT id, username, email, display_name, role, created_at, last_login_at FROM operators ORDER BY id ASC")
            return [dict(r) for r in cur.fetchall()]

    # ---- sessions ----
    def start_session(self, ssid, network_context, interface, source="live", operator_id=None):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (started_at, network_ssid, network_context, interface, source, operator_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (time.time(), ssid, network_context, interface, source, operator_id),
            )
            return cur.lastrowid

    def end_session(self, session_id):
        with self.cursor() as cur:
            cur.execute("UPDATE sessions SET ended_at = ? WHERE id = ?", (time.time(), session_id))

    def get_session(self, session_id: int):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_operator_sessions(self, operator_id: int | None = None):
        with self.cursor() as cur:
            if operator_id is not None:
                cur.execute(
                    "SELECT s.*, COUNT(e.id) as event_count "
                    "FROM sessions s LEFT JOIN events e ON s.id = e.session_id "
                    "WHERE s.operator_id = ? "
                    "GROUP BY s.id ORDER BY s.started_at DESC",
                    (operator_id,),
                )
            else:
                cur.execute(
                    "SELECT s.*, COUNT(e.id) as event_count "
                    "FROM sessions s LEFT JOIN events e ON s.id = e.session_id "
                    "GROUP BY s.id ORDER BY s.started_at DESC"
                )
            return [dict(r) for r in cur.fetchall()]

    # ---- events ----
    def log_event(self, session_id, detection_type, source_ip, target, severity,
                   confidence, risk_score, evidence: dict, recommended_action=""):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO events (session_id, ts, detection_type, source_ip, target, "
                "severity, confidence, risk_score, evidence_json, recommended_action, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), detection_type, source_ip, target, severity,
                 confidence, risk_score, json.dumps(evidence), recommended_action, "NEW"),
            )
            return cur.lastrowid

    def get_events(self, session_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE session_id = ? ORDER BY ts ASC", (session_id,))
            return [dict(r) for r in cur.fetchall()]

    # ---- actions ----
    def log_action(self, session_id, event_id, action, target, confirmed_by_user, notes=""):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO actions (session_id, event_id, ts, action, target, confirmed_by_user, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session_id, event_id, time.time(), action, target, int(confirmed_by_user), notes),
            )
            return cur.lastrowid

    def get_actions(self, session_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM actions WHERE session_id = ? ORDER BY ts ASC", (session_id,))
            return [dict(r) for r in cur.fetchall()]

    # ---- threat intel cache ----
    def get_cached_ip(self, ip):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,))
            row = cur.fetchone()
            return dict(row) if row else None

    def cache_ip(self, ip, abuse_confidence_score, country, asn, isp, raw_json):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO threat_intel_cache (ip, fetched_at, abuse_confidence_score, country, asn, isp, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET fetched_at=excluded.fetched_at, "
                "abuse_confidence_score=excluded.abuse_confidence_score, country=excluded.country, "
                "asn=excluded.asn, isp=excluded.isp, raw_json=excluded.raw_json",
                (ip, time.time(), abuse_confidence_score, country, asn, isp, raw_json),
            )

    # ---- operator config ----
    def get_config(self, key: str, default: str = "") -> str:
        with self.cursor() as cur:
            cur.execute("SELECT value FROM operator_config WHERE key = ?", (key,))
            row = cur.fetchone()
            return str(row["value"]) if row else default

    def set_config(self, key: str, value: str):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

