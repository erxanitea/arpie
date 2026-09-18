import datetime
import json

from arpie.views.theme import SEVERITY_BG, SEVERITY_COLORS


from arpie.views.mixins._typing import MixinBase


class SessionRestoreMixin(MixinBase):
    """Rehydrates in-memory app state (alerts, inventory, traffic history) from the DB snapshot."""

    def _restore_session_from_db(self):
        latest = self.db.get_latest_session(self.operator_id)
        if not latest:
            return
        self.session_id = latest["id"]
        raw_events = self.db.get_events(self.session_id)
        if raw_events:
            alerts = []
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
                    "type": e["detection_type"].replace("_", " ").title(),
                    "severity": e["severity"].upper(),
                    "source": e["source_ip"] or "Unknown",
                    "target": e.get("target") or "Local Endpoint",
                    "status": e.get("status", "NEW"),
                    "fg": SEVERITY_COLORS.get(e["severity"].lower(), "#DC2626"),
                    "bg": SEVERITY_BG.get(e["severity"].lower(), "#FEE2E2"),
                    "desc": ev_data.get("description", str(ev_data)),
                    "action": e.get("recommended_action") or "",
                    "confidence": e.get("confidence", 0.0),
                    "risk_score": e.get("risk_score", 0),
                    "evidence": ev_data,
                })
            self.all_alerts_list = alerts
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
