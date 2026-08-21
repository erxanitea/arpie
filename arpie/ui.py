"""
Flet desktop dashboard: real-time alerts, network-context indicator,
session risk gauge, Seal Mode confirmation, and report export.

Run with: `python main.py` (wraps `ft.app(target=main)`), or packaged
as a standalone .exe via PyInstaller — see README.md.
"""

import threading
import time

import flet as ft

from .capture import LiveCapture, PcapReplay
from .config import CONFIG
from .db import Database
from .detection import DetectionEngine
from .network_context import detect_network_context
from .report import build_report_data, export_html, export_json, export_pdf
from .risk import risk_band, score_alert, session_risk_score
from .seal import SealManager
from .threat_intel import ThreatIntelClient


SEVERITY_COLORS = {
    "low": ft.Colors.GREEN,
    "medium": ft.Colors.AMBER,
    "high": ft.Colors.ORANGE,
    "critical": ft.Colors.RED,
}


class ArpieApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.db = Database(CONFIG.db_path)
        self.threat_intel = ThreatIntelClient(self.db, CONFIG.threat_intel)
        self.alerts = []
        self.enrichments = {}
        self.session_id = None
        self.engine = None
        self.seal_mgr = None
        self.live_capture = None
        self.capture_thread = None

        self._build_ui()

    # ---------------- UI construction ----------------
    def _build_ui(self):
        self.page.title = f"{CONFIG.app_name} — Cyber-Detective Seal"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.padding = 20

        self.context_text = ft.Text("Network context: not yet detected", size=14)
        self.risk_text = ft.Text("Session risk: 0", size=22, weight=ft.FontWeight.BOLD)
        self.risk_bar = ft.ProgressBar(value=0, width=300)
        self.status_text = ft.Text("Idle", italic=True, color=ft.Colors.GREY)

        self.alert_list = ft.ListView(expand=True, spacing=8, auto_scroll=True)

        self.pcap_field = ft.TextField(label="PCAP file path (optional)", width=350)
        self.start_btn = ft.ElevatedButton("Start Monitoring", icon=ft.Icons.PLAY_ARROW,
                                            on_click=self.on_start)
        self.stop_btn = ft.ElevatedButton("Stop", icon=ft.Icons.STOP, on_click=self.on_stop,
                                           disabled=True)
        self.replay_btn = ft.ElevatedButton("Replay PCAP", icon=ft.Icons.UPLOAD_FILE,
                                             on_click=self.on_replay)
        self.export_json_btn = ft.OutlinedButton("Export JSON", on_click=lambda e: self.on_export("json"))
        self.export_html_btn = ft.OutlinedButton("Export HTML", on_click=lambda e: self.on_export("html"))
        self.export_pdf_btn = ft.OutlinedButton("Export PDF", on_click=lambda e: self.on_export("pdf"))

        self.page.add(
            ft.Row([ft.Text(CONFIG.app_name, size=28, weight=ft.FontWeight.BOLD),
                    ft.Text("Safe. Secure. Sealed.", italic=True, color=ft.Colors.GREY)]),
            ft.Divider(),
            ft.Row([self.context_text]),
            ft.Row([self.risk_text]),
            ft.Row([self.risk_bar]),
            self.status_text,
            ft.Row([self.start_btn, self.stop_btn, self.pcap_field, self.replay_btn]),
            ft.Row([self.export_json_btn, self.export_html_btn, self.export_pdf_btn]),
            ft.Divider(),
            ft.Text("Real-Time Alerts", size=18, weight=ft.FontWeight.BOLD),
            ft.Container(self.alert_list, expand=True, border=ft.Border.all(1, ft.Colors.GREY_300),
                          border_radius=8, padding=10, height=350),
        )

    # ---------------- session lifecycle ----------------
    def on_start(self, e):
        ctx = detect_network_context()
        self.context_text.value = (
            f"Network context: {ctx.classification.upper()}  |  "
            f"SSID: {ctx.ssid or 'unknown'}  |  Interface: {ctx.interface or 'unknown'}  |  "
            f"Gateway: {ctx.gateway_ip or 'unknown'}"
        )
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="live")
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)
        self.seal_mgr = SealManager(self.db, self.session_id, CONFIG.seal.auto_restore_seconds)

        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self.status_text.value = "Monitoring live traffic..."
        self.page.update()

        self.live_capture = LiveCapture(ctx.interface, self._on_packet)
        self.capture_thread = threading.Thread(target=self.live_capture.start, daemon=True)
        self.capture_thread.start()

    def on_stop(self, e):
        if self.live_capture:
            self.live_capture.stop()
        if self.session_id:
            self.db.end_session(self.session_id)
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        self.status_text.value = "Stopped."
        self.page.update()

    def on_replay(self, e):
        path = self.pcap_field.value
        if not path:
            self.status_text.value = "Enter a PCAP path first."
            self.page.update()
            return
        ctx = detect_network_context()
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface,
                                                  source=path)
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)
        self.seal_mgr = SealManager(self.db, self.session_id, CONFIG.seal.auto_restore_seconds)
        self.status_text.value = f"Replaying {path}..."
        self.page.update()

        replay = PcapReplay(path, self._on_packet)

        def run():
            count = replay.run()
            self.status_text.value = f"Replay complete — {count} packets processed."
            self.db.end_session(self.session_id)
            self.page.update()

        threading.Thread(target=run, daemon=True).start()

    # ---------------- packet -> alert -> UI pipeline ----------------
    def _on_packet(self, packet):
        alerts = self.engine.process(packet)
        for alert in alerts:
            self.alerts.append(alert)
            enrichment = None
            if alert.source_ip:
                enrichment = self.threat_intel.enrich(alert.source_ip)
                if enrichment:
                    self.enrichments[alert.source_ip] = enrichment

            score = score_alert(alert, enrichment)
            event_id = self.db.log_event(
                self.session_id, alert.detection_type, alert.source_ip, alert.target,
                alert.severity, alert.confidence, score, alert.evidence,
                alert.recommended_action,
            )
            self._render_alert(alert, score, event_id, enrichment)

        if alerts:
            overall = session_risk_score(self.alerts, self.enrichments)
            self.risk_text.value = f"Session risk: {overall} ({risk_band(overall)})"
            self.risk_bar.value = overall / 100
            self.page.update()

    def _render_alert(self, alert, score, event_id, enrichment):
        color = SEVERITY_COLORS.get(alert.severity, ft.Colors.GREY)
        enrichment_line = ""
        if enrichment:
            enrichment_line = (
                f"AbuseIPDB: {enrichment.abuse_confidence_score}  |  "
                f"{enrichment.country or '?'}  |  {enrichment.isp or '?'}"
            )

        seal_btn = ft.ElevatedButton(
            "Enable Seal Mode", icon=ft.Icons.LOCK,
            on_click=lambda e, ip=alert.target, eid=event_id: self._confirm_seal(ip, eid),
        )

        card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Container(ft.Text(alert.severity.upper(), color=ft.Colors.WHITE, weight=ft.FontWeight.BOLD),
                                 bgcolor=color, padding=6, border_radius=4),
                    ft.Text(alert.detection_type.replace("_", " ").title(), weight=ft.FontWeight.BOLD),
                    ft.Text(f"Confidence: {alert.confidence:.0%}"),
                    ft.Text(f"Risk: {score}"),
                ]),
                ft.Text(f"Source: {alert.source_ip}  →  Target: {alert.target}"),
                ft.Text(alert.evidence.get("reason", str(alert.evidence)), size=12, color=ft.Colors.GREY_700),
                ft.Text(enrichment_line, size=12, color=ft.Colors.GREY_700) if enrichment_line else ft.Container(),
                ft.Text(f"Recommended: {alert.recommended_action}", size=12, italic=True),
                ft.Row([seal_btn]),
            ]),
            border=ft.Border.all(1, ft.Colors.GREY_300),
            border_radius=8, padding=12, bgcolor=ft.Colors.GREY_50,
        )
        self.alert_list.controls.append(card)

    # ---------------- Seal Mode confirmation ----------------
    def _confirm_seal(self, target_ip, event_id):
        def do_seal(e):
            self.page.close(dlg)
            result = self.seal_mgr.seal(target_ip, event_id, confirmed_by_user=True)
            self.status_text.value = result.message
            self.page.update()

        def cancel(e):
            self.page.close(dlg)
            self.db.log_action(self.session_id, event_id, "dismiss", target_ip,
                                confirmed_by_user=True, notes="User dismissed Seal Mode prompt")

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm Seal Mode"),
            content=ft.Text(
                f"This will apply a temporary firewall rule blocking {target_ip}. "
                f"It auto-restores in {CONFIG.seal.auto_restore_seconds // 60} minutes, "
                f"or you can Unseal manually. Continue?"
            ),
            actions=[ft.TextButton("Cancel", on_click=cancel),
                     ft.ElevatedButton("Confirm", on_click=do_seal)],
        )
        self.page.open(dlg)

    # ---------------- report export ----------------
    def on_export(self, fmt: str):
        if not self.session_id:
            self.status_text.value = "No active/completed session to export."
            self.page.update()
            return
        data = build_report_data(self.db, self.session_id)
        out_path = f"arpie_session_{self.session_id}.{fmt}"
        if fmt == "json":
            export_json(data, out_path)
        elif fmt == "html":
            export_html(data, out_path)
        elif fmt == "pdf":
            export_pdf(data, out_path)
        self.status_text.value = f"Exported report to {out_path}"
        self.page.update()


def main(page: ft.Page):
    ArpieApp(page)


def run():
    ft.app(target=main)
