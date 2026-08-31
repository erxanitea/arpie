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
