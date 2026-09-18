"""Command-line and desktop entry points for Arpie."""

import argparse
import json
import os

os.environ["GTK_A11Y"] = "none"
os.environ["GDK_DEBUG"] = "misc"
os.environ["G_MESSAGES_DEBUG"] = ""

from arpie.infrastructure.capture import PcapReplay
from arpie.config import CONFIG
from arpie.detection import DetectionEngine
from arpie.models import Database
from arpie.network import detect_network_context
from arpie.detection import risk_band, score_alert, session_risk_score
from arpie.infrastructure.threat_intel import ThreatIntelClient


def run_cli_pcap(path: str, gateway_ip: str | None = None):
    ctx = detect_network_context()
    effective_gateway = gateway_ip or ctx.gateway_ip
    db = Database(CONFIG.db_path)
    intel = ThreatIntelClient(db, CONFIG.threat_intel)
    engine = DetectionEngine(CONFIG.thresholds, gateway_ip=effective_gateway)
    session_id = db.start_session(ctx.ssid, ctx.classification, ctx.interface, source=path)
    all_alerts = []
    enrichments = {}

    def on_packet(packet):
        for alert in engine.process(packet):
            all_alerts.append(alert)
            enrichment = intel.enrich(alert.source_ip) if alert.source_ip else None
            if enrichment:
                enrichments[alert.source_ip] = enrichment
            score = score_alert(alert, enrichment)
            db.log_event(session_id, alert.detection_type, alert.source_ip, alert.target,
                         alert.severity, alert.confidence, score, alert.evidence,
                         alert.recommended_action, ts=alert.ts)
            print(json.dumps({
                "type": alert.detection_type,
                "source": alert.source_ip,
                "target": alert.target,
                "severity": alert.severity,
                "confidence": alert.confidence,
                "risk_score": score,
                "evidence": alert.evidence,
            }, indent=2))

    count = PcapReplay(path, on_packet).run()
    db.end_session(session_id)
    overall = session_risk_score(all_alerts, enrichments)
    print(f"\n--- Processed {count} packets | {len(all_alerts)} alerts | "
          f"Session risk: {overall} ({risk_band(overall)}) ---")


def run_gui():
    from arpie.views.app import ArpieApp
    import flet as ft
    ft.run(lambda page: ArpieApp(page), view=ft.AppView.FLET_APP)


def main():
    parser = argparse.ArgumentParser(description="Arpie — Endpoint NIDS for Public Wi-Fi")
    parser.add_argument("--pcap", help="Replay a PCAP file in headless CLI mode")
    parser.add_argument("--gateway-ip", help="Override gateway IP")
    args = parser.parse_args()
    if args.pcap:
        run_cli_pcap(args.pcap, gateway_ip=args.gateway_ip)
    else:
        run_gui()


if __name__ == "__main__":
    main()
