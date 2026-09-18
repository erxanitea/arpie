from pathlib import Path
import threading

from arpie.infrastructure.capture import PcapReplay
from arpie.config import CONFIG
from arpie.detection import DetectionEngine
from arpie.network import detect_network_context


class CaptureController:

    def __init__(self, app):
        self.app = app

    def run_pcap_replay(self, pcap_path: str):
        requested_path = Path(pcap_path).expanduser()
        if not requested_path.exists():
            repository_path = Path(__file__).resolve().parents[2] / requested_path
            if repository_path.exists():
                requested_path = repository_path

        if not requested_path.is_file():
            self.app.status_toast = f"PCAP file not found: {pcap_path}"
            self.app.update_view_content()
            self.app.page.update()
            return

        resolved_path = str(requested_path.resolve())
        ctx = detect_network_context()
        self.app.session_id = self.app.db.start_session(
            ctx.ssid,
            ctx.classification,
            ctx.interface,
            source=resolved_path,
            operator_id=self.app.operator_id,
        )
        self.app.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)

        replay = PcapReplay(resolved_path, self.app._process_packet)
        threading.Thread(target=replay.run, daemon=True).start()
        label = "Demo capture replay" if requested_path.name == "demo_attack.pcap" else "Replaying PCAP"
        self.app.status_toast = f"{label}: {requested_path.name}"
        self.app.update_view_content()
        self.app.page.update()