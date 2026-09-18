import base64
import hashlib
import hmac
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


# scrypt "interactive login" parameters (RFC 7914): ~16 MB and ~30 ms per
# derivation, which is cheap for a desktop login and expensive to attack in bulk.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_DK_LEN = 32


SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'End User',
    totp_secret TEXT,
    recovery_codes TEXT,
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


class DatabaseBase:
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
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(operators)")
            cols = {row["name"] for row in cur.fetchall()}
            if "totp_secret" not in cols:
                conn.execute("ALTER TABLE operators ADD COLUMN totp_secret TEXT")
            if "recovery_codes" not in cols:
                conn.execute("ALTER TABLE operators ADD COLUMN recovery_codes TEXT")

            cur.execute("PRAGMA table_info(sessions)")
            s_cols = {row["name"] for row in cur.fetchall()}
            if "operator_id" not in s_cols:
                conn.execute("ALTER TABLE sessions ADD COLUMN operator_id INTEGER")
            conn.commit()

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
        """Derive a salted scrypt hash, stored as ``scrypt$N$r$p$salt_b64$key_b64``."""
        salt = secrets.token_bytes(_SALT_BYTES)
        key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_DK_LEN,
        )
        return "scrypt${}${}${}${}${}".format(
            _SCRYPT_N,
            _SCRYPT_R,
            _SCRYPT_P,
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(key).decode("ascii"),
        )

    @staticmethod
    def _verify_password(stored: str, password: str) -> tuple[bool, bool]:
        """Return ``(is_valid, needs_rehash)`` for a stored password hash.

        Accounts created before salted hashing carry a bare SHA-256 hex digest.
        Those still verify, but are flagged so the caller can transparently
        re-hash them with the current scheme on a successful login.
        """
        stored = (stored or "").strip()
        if not stored:
            return False, False

        if stored.startswith("scrypt$"):
            try:
                _, n_s, r_s, p_s, salt_b64, key_b64 = stored.split("$")
                expected = base64.b64decode(salt_b64), base64.b64decode(key_b64)
                key = hashlib.scrypt(
                    password.encode("utf-8"),
                    salt=expected[0],
                    n=int(n_s),
                    r=int(r_s),
                    p=int(p_s),
                    dklen=len(expected[1]),
                )
            except (ValueError, TypeError):
                return False, False
            return hmac.compare_digest(key, expected[1]), False

        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        ok = hmac.compare_digest(stored, legacy)
        return ok, ok

    @staticmethod
    def _public_operator(row) -> dict:
        """Strip credential material before an operator row enters app state."""
        operator = dict(row)
        operator.pop("password_hash", None)
        operator.pop("recovery_codes", None)
        return operator
