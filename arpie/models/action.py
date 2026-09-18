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
