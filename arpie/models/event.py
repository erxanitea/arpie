import json
import time

from ._typing import MixinBase


class EventMixin(MixinBase):

    def log_event(self, session_id, detection_type, source_ip, target, severity,
                   confidence, risk_score, evidence: dict, recommended_action=""):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO events (session_id, ts, detection_type, source_ip, target, "
                "severity, confidence, risk_score, evidence_json, recommended_action, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, time.time(), detection_type, source_ip, target, severity,
                 confidence, risk_score, json.dumps(evidence), recommended_action, "NEW"),
            )
            return cur.lastrowid

    def get_events(self, session_id):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM events WHERE session_id = ? ORDER BY ts ASC", (session_id,))
            return [dict(r) for r in cur.fetchall()]
