import time

from arpie.models._typing import MixinBase


class ActionMixin(MixinBase):

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

    def record_seal(self, target: str, session_id=None, reason: str = ""):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO seals (target, sealed_at, session_id, reason, active) "
                "VALUES (?, ?, ?, ?, 1) "
                "ON CONFLICT(target) DO UPDATE SET sealed_at=excluded.sealed_at, "
                "session_id=excluded.session_id, reason=excluded.reason, active=1",
                (target, time.time(), session_id, reason),
            )

    def clear_seal(self, target: str):
        with self.cursor() as cur:
            cur.execute("UPDATE seals SET active = 0 WHERE target = ?", (target,))

    def get_active_seals(self) -> list[dict]:
        with self.cursor() as cur:
            cur.execute("SELECT * FROM seals WHERE active = 1 ORDER BY sealed_at DESC")
            return [dict(r) for r in cur.fetchall()]
