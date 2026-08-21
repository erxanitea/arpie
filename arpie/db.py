"""
SQLite storage for sessions, events, evidence, scores, and actions.
"""

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    ended_at REAL,
    network_ssid TEXT,
    network_context TEXT,          -- trusted / public-untrusted / unknown
    interface TEXT,
    source TEXT                    -- 'live' or pcap filename
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

    # ---- sessions ----
    def start_session(self, ssid, network_context, interface, source="live"):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO sessions (started_at, network_ssid, network_context, interface, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), ssid, network_context, interface, source),
            )
            return cur.lastrowid

    def end_session(self, session_id):
        with self.cursor() as cur:
            cur.execute("UPDATE sessions SET ended_at = ? WHERE id = ?", (time.time(), session_id))

    # ---- events ----
    def log_event(self, session_id, detection_type, source_ip, target, severity,
                   confidence, risk_score, evidence: dict, recommended_action=""):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO events (session_id, ts, detection_type, source_ip, target, "
                "severity, confidence, risk_score, evidence_json, recommended_action) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), detection_type, source_ip, target, severity,
                 confidence, risk_score, json.dumps(evidence), recommended_action),
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
