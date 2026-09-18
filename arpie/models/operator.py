import json
import time

from arpie.models._typing import MixinBase


class OperatorMixin(MixinBase):

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
            if not row:
                return None

            valid, needs_rehash = self._verify_password(row["password_hash"], password)
            if not valid:
                return None

            if needs_rehash:
                cur.execute(
                    "UPDATE operators SET password_hash = ? WHERE id = ?",
                    (self._hash_password(password), row["id"]),
                )
            cur.execute("UPDATE operators SET last_login_at = ? WHERE id = ?", (time.time(), row["id"]))
            return self._public_operator(row)

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

    def get_totp_secret(self, username: str) -> str | None:
        with self.cursor() as cur:
            cur.execute("SELECT totp_secret FROM operators WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            row = cur.fetchone()
            return row["totp_secret"] if row and row["totp_secret"] else None

    def set_totp_secret(self, username: str, secret: str | None) -> bool:
        with self.cursor() as cur:
            cur.execute(
                "UPDATE operators SET totp_secret = ? WHERE LOWER(username) = LOWER(?)",
                (secret, username.strip()),
            )
            return cur.rowcount > 0

    def get_recovery_codes(self, username: str) -> list[str]:
        with self.cursor() as cur:
            cur.execute("SELECT recovery_codes FROM operators WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            row = cur.fetchone()
            if row and row["recovery_codes"]:
                return json.loads(row["recovery_codes"])
            return []

    def set_recovery_codes(self, username: str, codes: list[str] | None) -> bool:
        val = json.dumps(codes) if codes else None
        with self.cursor() as cur:
            cur.execute(
                "UPDATE operators SET recovery_codes = ? WHERE LOWER(username) = LOWER(?)",
                (val, username.strip()),
            )
            return cur.rowcount > 0

    def consume_recovery_code(self, username: str, code: str) -> bool:
        codes = self.get_recovery_codes(username)
        normalized = code.strip().lower().replace("-", "").replace(" ", "")
        for i, c in enumerate(codes):
            if c.lower().replace("-", "") == normalized:
                codes.pop(i)
                self.set_recovery_codes(username, codes)
                return True
        return False
