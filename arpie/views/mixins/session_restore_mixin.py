import datetime
import json
import time

from arpie.views.theme import SEVERITY_BG, SEVERITY_COLORS
from arpie.models import Alert


from arpie.views.mixins._typing import MixinBase


class SessionRestoreMixin(MixinBase):
    """Rehydrates in-memory app state (alerts, inventory, traffic history) from the DB snapshot."""

    def _restore_session_from_db(self):
        latest = self.db.get_latest_session(self.operator_id)
        if not latest:
            return
        self.session_id = latest["id"]
        started_at = float(latest.get("started_at") or 0.0)
        ended_at = float(latest.get("ended_at") or 0.0)
        if started_at > 0:
            duration = max(0, int((ended_at or time.time()) - started_at)) if ended_at else 0
            self.accumulated_seconds = float(duration)
            hrs = duration // 3600
            mins = (duration % 3600) // 60
            secs = duration % 60
            timestr = f"{hrs:02d}:{mins:02d}:{secs:02d}"
            self.timer_text.value = timestr
            self.sidebar_timer_text.value = timestr
        raw_events = self.db.get_events(self.session_id)
        if raw_events:
            alerts = []
            reconstructed_alerts = []
            for e in raw_events:
                ev_data = {}
                try:
                    ev_data = json.loads(e.get("evidence_json", "{}"))
                except Exception:
                    pass
                alerts.append({
                    "id": e["id"],
                    "time": datetime.datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S"),
                    "date": datetime.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d"),
                    "type": str(e["detection_type"]).replace("_", " ").title(),
                    "severity": str(e["severity"]).upper(),
                    "source": str(e["source_ip"]) if e.get("source_ip") else "Unknown",
                    "target": str(e.get("target") or "Local Endpoint"),
                    "status": str(e.get("status", "NEW")),
                    "fg": SEVERITY_COLORS.get(str(e["severity"]).lower(), "#DC2626"),
                    "bg": SEVERITY_BG.get(str(e["severity"]).lower(), "#FEE2E2"),
                    "desc": ev_data.get("reason") or ev_data.get("description") or e.get("recommended_action") or str(ev_data),
                    "action": str(e.get("recommended_action") or ""),
                    "confidence": float(e.get("confidence", 0.0)),
                    "risk_score": int(e.get("risk_score", 0)),
                    "evidence": ev_data,
                })
                reconstructed_alerts.append(
                    Alert(
                        detection_type=str(e["detection_type"]),
                        source_ip=str(e["source_ip"]) if e.get("source_ip") else None,
                        target=str(e["target"]) if e.get("target") else None,
                        severity=str(e["severity"]).lower(),
                        confidence=float(e.get("confidence", 0.0)),
                        evidence=ev_data if isinstance(ev_data, dict) else {},
                        recommended_action=str(e.get("recommended_action") or ""),
                        ts=float(e.get("ts", 0.0)),
                    )
                )
            self.all_alerts_list = alerts
            self.alerts = reconstructed_alerts
            self.threats_count = len(alerts)


        dev_json = self.db.get_config("snapshot_devices", "")
        if dev_json:
            try:
                loaded_devs = json.loads(dev_json)
                if isinstance(loaded_devs, list):
                    for idx, d in enumerate(loaded_devs):
                        if isinstance(d, dict):
                            if "id" not in d:
                                d["id"] = str(idx + 1)
                            if "last_seen" not in d:
                                d["last_seen"] = "Just now"
                    self.devices_inventory = loaded_devs
            except Exception:
                pass

        pkt_count = self.db.get_config("snapshot_packets", "")
        if pkt_count:
            try:
                self.packets_count = int(pkt_count)
            except Exception:
                pass

        packet_log_json = self.db.get_config("snapshot_packet_log", "")
        if packet_log_json:
            try:
                loaded_packet_log = json.loads(packet_log_json)
                if isinstance(loaded_packet_log, list):
                    self.packet_log_stream = loaded_packet_log
            except Exception:
                pass

        traffic_json = self.db.get_config("snapshot_traffic", "")
        if traffic_json:
            try:
                self.traffic_history = json.loads(traffic_json)
            except Exception:
                pass

        talkers_json = self.db.get_config("snapshot_top_talkers", "")
        if talkers_json:
            try:
                self.top_talkers_data = json.loads(talkers_json)
            except Exception:
                pass

        if self.traffic_history:
            now_dt = datetime.datetime.now()
            cnt = len(self.traffic_history)
            step_sec = max(1, getattr(self, "traffic_interval_sec", 1))
            self.traffic_timestamps = [
                (now_dt - datetime.timedelta(seconds=(cnt - 1 - i) * step_sec)).strftime("%H:%M:%S")
                for i in range(cnt)
            ]
