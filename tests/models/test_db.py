import tempfile
import os
import pytest
from arpie.models import Database


def test_fresh_database_has_no_operators():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        assert db.has_operators() is False
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_setup_admin_and_end_user_lifecycle():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        assert db.has_operators() is False

        # 1. First-run: Installer sets up primary admin account
        admin_id = db.create_operator("evaluator", "evaluator@university.edu", "masterkey123", display_name="Dr. Evaluator", role="Evaluator/Administrator")
        assert admin_id is not None
        assert db.has_operators() is True

        # Verify admin login via username and email
        admin_by_user = db.authenticate_operator("evaluator", "masterkey123")
        assert admin_by_user is not None
        assert admin_by_user["role"] == "Evaluator/Administrator"

        admin_by_email = db.authenticate_operator("evaluator@university.edu", "masterkey123")
        assert admin_by_email is not None
        assert admin_by_email["username"] == "evaluator"

        # 2. Subsequent registration: Standard End User account
        user_id = db.create_operator("student_era", "era@univ.edu", "studyPass789", display_name="Era Dumangcas", role="End User")
        assert user_id is not None

        user = db.authenticate_operator("student_era", "studyPass789")
        assert user is not None
        assert user["role"] == "End User"
        assert user["email"] == "era@univ.edu"

        # 3. Invalid credentials rejected
        assert db.authenticate_operator("evaluator", "wrongpass") is None
        assert db.authenticate_operator("student_era", "wrongpass") is None

        # 4. TOTP secret management
        assert db.get_totp_secret("evaluator") is None
        db.set_totp_secret("evaluator", "JBSWY3DPEHPK3PXP")
        assert db.get_totp_secret("evaluator") == "JBSWY3DPEHPK3PXP"
        db.set_totp_secret("evaluator", None)
        assert db.get_totp_secret("evaluator") is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_passwords_are_salted_and_never_stored_in_plain_digest_form():
    """Two operators sharing a password must not share a stored hash, and no
    stored hash may be a bare SHA-256 digest (unsalted, single round)."""
    import hashlib
    import sqlite3

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        db.create_operator("alice", "alice@univ.edu", "sharedPass123")
        db.create_operator("bob", "bob@univ.edu", "sharedPass123")

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT username, password_hash FROM operators").fetchall()
        conn.close()

        hashes = {r["username"]: r["password_hash"] for r in rows}
        assert hashes["alice"] != hashes["bob"], "identical passwords produced identical hashes"

        legacy = hashlib.sha256(b"sharedPass123").hexdigest()
        for stored in hashes.values():
            assert stored != legacy
            assert stored.startswith("scrypt$")

        assert db.authenticate_operator("alice", "sharedPass123") is not None
        assert db.authenticate_operator("bob", "sharedPass123") is not None
        assert db.authenticate_operator("alice", "sharedPass124") is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_legacy_sha256_account_authenticates_then_upgrades():
    """Accounts written by the pre-salt scheme must keep working and be
    transparently re-hashed on the next successful login."""
    import hashlib
    import sqlite3

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        db.create_operator("legacy_user", "legacy@univ.edu", "placeholder")

        # Rewrite the row the way the old _hash_password would have stored it.
        legacy = hashlib.sha256("oldPassword1".encode("utf-8")).hexdigest()
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE operators SET password_hash = ? WHERE username = ?", (legacy, "legacy_user"))
        conn.commit()
        conn.close()

        assert db.authenticate_operator("legacy_user", "wrongpass") is None
        assert db.authenticate_operator("legacy_user", "oldPassword1") is not None

        conn = sqlite3.connect(db_path)
        upgraded = conn.execute(
            "SELECT password_hash FROM operators WHERE username = ?", ("legacy_user",)
        ).fetchone()[0]
        conn.close()
        assert upgraded.startswith("scrypt$"), "legacy hash was not upgraded on login"

        assert db.authenticate_operator("legacy_user", "oldPassword1") is not None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_authenticate_does_not_leak_credential_material():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        db.create_operator("carol", "carol@univ.edu", "carolPass123")
        db.set_recovery_codes("carol", ["AAAA-BBBB", "CCCC-DDDD"])

        operator = db.authenticate_operator("carol", "carolPass123")
        assert operator is not None
        assert "password_hash" not in operator
        assert "recovery_codes" not in operator
        assert operator["username"] == "carol"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_update_event_status():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        op_id = db.create_operator("alice", "alice@example.com", "passWord123")
        session_id = db.start_session("TestSSID", "trusted", "wlan0", operator_id=op_id)
        ev_id = db.log_event(
            session_id, "arp_spoof", "192.168.1.1", "192.168.1.1", "high",
            0.87, 85, {"reason": "2 MACs"}, "Seal host",
        )
        events = db.get_events(session_id)
        assert len(events) == 1
        assert events[0]["status"] == "NEW"
        assert ev_id is not None

        db.update_event_status(ev_id, "ACKNOWLEDGED")
        events_after = db.get_events(session_id)
        assert events_after[0]["status"] == "ACKNOWLEDGED"

        db.update_event_status(ev_id, "RESOLVED")
        events_resolved = db.get_events(session_id)
        assert events_resolved[0]["status"] == "RESOLVED"
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

