import tempfile
import os
import pytest
from arpie.db import Database


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
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_passwords_are_salted_and_unique():
    """Two accounts with the same password must not share a stored hash."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        db.create_operator("u1", "u1@x.com", "samepass", role="End User")
        db.create_operator("u2", "u2@x.com", "samepass", role="End User")
        h1 = db.get_operator("u1")["password_hash"]
        h2 = db.get_operator("u2")["password_hash"]
        assert h1.startswith("scrypt$") and h2.startswith("scrypt$")
        assert h1 != h2  # per-user salt
        assert db.authenticate_operator("u1", "samepass") is not None
        assert db.authenticate_operator("u1", "wrong") is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_legacy_sha256_hash_migrates_on_login():
    """A pre-upgrade unsalted SHA-256 row must still authenticate and be
    transparently rewritten as salted scrypt."""
    import hashlib
    import sqlite3
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        db = Database(db_path)
        db.create_operator("legacy", "legacy@x.com", "placeholder", role="End User")
        legacy = hashlib.sha256(b"realpass").hexdigest()
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE operators SET password_hash = ? WHERE username = ?", (legacy, "legacy"))
        conn.commit()
        conn.close()

        assert db.authenticate_operator("legacy", "realpass") is not None
        assert db.get_operator("legacy")["password_hash"].startswith("scrypt$")
        assert db.authenticate_operator("legacy", "realpass") is not None
        assert db.authenticate_operator("legacy", "realpass2") is None
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
