import time

from arpie.models._typing import MixinBase


class SessionMixin(MixinBase):

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

    def get_latest_session(self, operator_id: int | None = None) -> dict | None:
        with self.cursor() as cur:
            if operator_id is not None:
                cur.execute(
                    "SELECT s.*, COUNT(e.id) as ev_cnt FROM sessions s "
                    "LEFT JOIN events e ON s.id = e.session_id "
                    "WHERE s.operator_id = ? "
                    "GROUP BY s.id "
                    "ORDER BY s.started_at DESC, s.id DESC LIMIT 1",
                    (operator_id,),
                )
            else:
                cur.execute(
                    "SELECT s.*, COUNT(e.id) as ev_cnt FROM sessions s "
                    "LEFT JOIN events e ON s.id = e.session_id "
                    "GROUP BY s.id "
                    "ORDER BY s.started_at DESC, s.id DESC LIMIT 1"
                )
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
