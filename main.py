"""
Arpie entry point.

Desktop app:   python main.py
CLI PCAP mode: python main.py --pcap path/to/file.pcap
"""

import argparse
import json
import sys

from arpie.config import CONFIG
from arpie.db import Database
from arpie.detection import DetectionEngine
from arpie.capture import PcapReplay
from arpie.network_context import detect_network_context
from arpie.risk import score_alert, session_risk_score, risk_band
from arpie.threat_intel import ThreatIntelClient


def run_cli_pcap(path: str):
    """Headless mode: replay a PCAP and print findings — used for grading/demo
    without needing a live capture-capable environment."""
    ctx = detect_network_context()
    db = Database(CONFIG.db_path)
    intel = ThreatIntelClient(db, CONFIG.threat_intel)
    engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)
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
                         alert.recommended_action)
            print(json.dumps({
                "type": alert.detection_type, "source": alert.source_ip,
                "target": alert.target, "severity": alert.severity,
                "confidence": alert.confidence, "risk_score": score,
                "evidence": alert.evidence,
            }, indent=2))

    replay = PcapReplay(path, on_packet)
    count = replay.run()
    db.end_session(session_id)

    overall = session_risk_score(all_alerts, enrichments)
    print(f"\n--- Processed {count} packets | {len(all_alerts)} alerts | "
          f"Session risk: {overall} ({risk_band(overall)}) ---")


def run_gui():
    from arpie.ui import run
    run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Arpie — Endpoint NIDS for Public Wi-Fi")
    parser.add_argument("--pcap", help="Replay a PCAP file in headless CLI mode", default=None)
    args = parser.parse_args()

    if args.pcap:
        run_cli_pcap(args.pcap)
    else:
        run_gui()
