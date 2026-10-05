import json
import time

from arpie.models._typing import MixinBase


class EventMixin(MixinBase):

    def log_event(self, session_id, detection_type, source_ip, target, severity,
                   confidence, risk_score, evidence: dict, recommended_action="", ts=None):
        """Record a detection event.

        `ts` is when the traffic was *observed* (``Alert.ts``). Callers should pass
        it so a replayed capture is filed under the original incident time rather
        than the time the replay happened to run. It defaults to now for callers
        with no captured packet behind them, such as the demo seeder.
        """
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO events (session_id, ts, detection_type, source_ip, target, "
                "severity, confidence, risk_score, evidence_json, recommended_action, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, time.time() if ts is None else float(ts), detection_type,
                 source_ip, target, severity,
                 confidence, risk_score, json.dumps(evidence), recommended_action, "NEW"),
            )
            return cur.lastrowid

    def get_events(self, session_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE session_id = ? ORDER BY ts ASC", (session_id,))
            return [dict(r) for r in cur.fetchall()]

    def update_event_status(self, event_id: int, status: str):
        with self.cursor() as cur:
            cur.execute("UPDATE events SET status = ? WHERE id = ?", (status, event_id))

