"""
Flet Desktop Dashboard for Arpie Endpoint NIDS.

Features:
- Real-time packet inspection & alert visualizer
- Network-context classifier indicator (Trusted / Public-Untrusted / Unknown)
- Dynamic heuristic session risk gauge (0 - 100)
- Reversible "Seal Mode" with automated iptables/netsh rule execution
- Forensic session report exports (PDF, HTML, JSON)
"""

import threading
import time
from typing import Optional

import flet as ft

from .capture import LiveCapture, PcapReplay
from .config import CONFIG
from .db import Database
from .detection import Alert, DetectionEngine
from .network_context import detect_network_context
from .notification import send_desktop_notification
from .report import build_report_data, export_html, export_json, export_pdf
from .risk import risk_band, score_alert, session_risk_score
from .seal import SealManager
from .threat_intel import IpEnrichment, ThreatIntelClient


SEVERITY_COLORS = {
    "low": "#10B981",       # Emerald
    "medium": "#F59E0B",    # Amber
    "high": "#F97316",      # Orange
    "critical": "#EF4444",  # Crimson
}

SEVERITY_BG = {
    "low": "#064E3B",
    "medium": "#78350F",
    "high": "#7C2D12",
    "critical": "#7F1D1D",
}


class ArpieApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.db = Database(CONFIG.db_path)
        self.threat_intel = ThreatIntelClient(self.db, CONFIG.threat_intel)
        self.alerts: list[Alert] = []
        self.enrichments: dict[str, IpEnrichment] = {}
        self.session_id: Optional[int] = None
        self.engine: Optional[DetectionEngine] = None
        self.seal_mgr: Optional[SealManager] = None
        self.live_capture: Optional[LiveCapture] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.active_blocks: list[str] = []

        self._build_ui()

    def _build_ui(self):
        self.page.title = f"{CONFIG.app_name} — Endpoint NIDS & Threat Response"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = "#0B0F19"
        self.page.padding = 20

        # ---- Header / Branding ----
        header = ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            controls=[
                ft.Row([
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#06B6D4", size=36),
                    ft.Column([
                        ft.Row([
                            ft.Text(CONFIG.app_name, size=24, weight=ft.FontWeight.BOLD, color="#F8FAFC"),
                            ft.Container(
                                content=ft.Text("ENDPOINT NIDS", size=10, weight=ft.FontWeight.BOLD, color="#06B6D4"),
                                bgcolor="#083344", padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                                border_radius=4,
                            ),
                        ], spacing=8),
                        ft.Text("Context-Aware Intrusion Detection & Reversible Threat-Response", size=12, color="#94A3B8"),
                    ], spacing=2),
                ], spacing=12),
                ft.Row([
                    ft.Container(content=None) # placeholder
                ])
            ]
        )
        self.status_chip_container = ft.Row([
            self._make_status_chip("IDLE", "#64748B", "#1E293B"),
        ])
        header.controls[1] = self.status_chip_container

        # ---- Network Context & KPI Metric Cards ----
        self.context_label = ft.Text("Not detected", size=13, weight=ft.FontWeight.BOLD, color="#F8FAFC")
        self.ssid_label = ft.Text("SSID: —", size=12, color="#94A3B8")
        self.iface_label = ft.Text("Interface: —", size=12, color="#94A3B8")
        self.gateway_label = ft.Text("Gateway: —", size=12, color="#94A3B8")

        self.risk_score_text = ft.Text("0", size=32, weight=ft.FontWeight.BOLD, color="#10B981")
        self.risk_band_text = ft.Text("LOW", size=11, weight=ft.FontWeight.BOLD, color="#10B981")
        self.risk_band_badge = ft.Container(
            content=self.risk_band_text,
            bgcolor="#064E3B", padding=ft.Padding.symmetric(horizontal=8, vertical=3),
            border_radius=4,
        )
        self.risk_progress = ft.ProgressBar(value=0.0, color="#10B981", bgcolor="#1E293B", height=8, border_radius=4)

        self.alerts_count_text = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color="#F8FAFC")
        self.intel_hits_text = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color="#06B6D4")
        self.blocks_count_text = ft.Text("0", size=26, weight=ft.FontWeight.BOLD, color="#F59E0B")

        # 3 KPI Cards Layout
        kpi_row = ft.ResponsiveRow([
            # Card 1: Network Context
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.WIFI_LOCK_ROUNDED, color="#06B6D4", size=20),
                        ft.Text("Network Context", size=14, weight=ft.FontWeight.BOLD, color="#E2E8F0"),
                    ]),
                    self.context_label,
                    self.ssid_label,
                    ft.Row([self.iface_label, self.gateway_label], spacing=16),
                ], spacing=4),
                bgcolor="#111827", border=ft.Border.all(1, "#1F2937"), border_radius=10, padding=14,
                col={"sm": 12, "md": 4},
            ),
            # Card 2: Session Risk Gauge
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SPEED_ROUNDED, color="#F59E0B", size=20),
                        ft.Text("Session Threat Gauge", size=14, weight=ft.FontWeight.BOLD, color="#E2E8F0"),
                        ft.Container(expand=True),
                        self.risk_band_badge,
                    ]),
                    ft.Row([
                        self.risk_score_text,
                        ft.Text("/ 100", size=14, color="#64748B", weight=ft.FontWeight.BOLD),
                    ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.BASELINE),
                    self.risk_progress,
                ], spacing=6),
                bgcolor="#111827", border=ft.Border.all(1, "#1F2937"), border_radius=10, padding=14,
                col={"sm": 12, "md": 4},
            ),
            # Card 3: Detections & Response Stats
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.ANALYTICS_OUTLINED, color="#10B981", size=20),
                        ft.Text("Incident Metrics", size=14, weight=ft.FontWeight.BOLD, color="#E2E8F0"),
                    ]),
                    ft.Row([
                        ft.Column([self.alerts_count_text, ft.Text("Alerts", size=11, color="#94A3B8")], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                        ft.Column([self.intel_hits_text, ft.Text("Intel Hits", size=11, color="#94A3B8")], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                        ft.Column([self.blocks_count_text, ft.Text("Sealed", size=11, color="#94A3B8")], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    ], alignment=ft.MainAxisAlignment.SPACE_AROUND),
                ], spacing=6),
                bgcolor="#111827", border=ft.Border.all(1, "#1F2937"), border_radius=10, padding=14,
                col={"sm": 12, "md": 4},
            ),
        ])

        # ---- Controls & Inputs Toolbar ----
        self.pcap_field = ft.TextField(
            label="PCAP File Path (e.g. sample_pcaps/demo_public_wifi.pcap)",
            hint_text="sample_pcaps/demo_public_wifi.pcap",
            expand=True, dense=True, text_size=13,
            bgcolor="#1E293B", border_color="#334155",
        )
        self.gateway_field = ft.TextField(
            label="Gateway Override (optional)",
            hint_text="192.168.1.1", width=180, dense=True, text_size=13,
            bgcolor="#1E293B", border_color="#334155",
        )

        self.start_btn = ft.ElevatedButton(
            "Start Monitoring", icon=ft.Icons.PLAY_ARROW_ROUNDED,
            on_click=self.on_start,
            style=ft.ButtonStyle(bgcolor="#0284C7", color="#FFFFFF", shape=ft.RoundedRectangleBorder(radius=6)),
        )
        self.stop_btn = ft.ElevatedButton(
            "Stop", icon=ft.Icons.STOP_ROUNDED,
            on_click=self.on_stop, disabled=True,
            style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", shape=ft.RoundedRectangleBorder(radius=6)),
        )
        self.replay_btn = ft.ElevatedButton(
            "Replay PCAP", icon=ft.Icons.FILE_OPEN_ROUNDED,
            on_click=self.on_replay,
            style=ft.ButtonStyle(bgcolor="#0D9488", color="#FFFFFF", shape=ft.RoundedRectangleBorder(radius=6)),
        )

        self.export_pdf_btn = ft.OutlinedButton("Export PDF", icon=ft.Icons.PICTURE_AS_PDF_ROUNDED, on_click=lambda e: self.on_export("pdf"))
        self.export_html_btn = ft.OutlinedButton("Export HTML", icon=ft.Icons.HTML_ROUNDED, on_click=lambda e: self.on_export("html"))
        self.export_json_btn = ft.OutlinedButton("Export JSON", icon=ft.Icons.DATA_OBJECT_ROUNDED, on_click=lambda e: self.on_export("json"))

        control_panel = ft.Container(
            content=ft.Column([
                ft.Row([self.pcap_field, self.gateway_field, self.replay_btn]),
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Row([self.start_btn, self.stop_btn]),
                        ft.Row([self.export_pdf_btn, self.export_html_btn, self.export_json_btn]),
                    ],
                ),
            ], spacing=12),
            bgcolor="#111827", border=ft.Border.all(1, "#1F2937"), border_radius=10, padding=14,
        )

        # ---- Real-Time Alerts Feed ----
        self.alert_list = ft.ListView(expand=True, spacing=10, auto_scroll=True)
        self.empty_state = ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.SECURITY_ROUNDED, size=44, color="#334155"),
                ft.Text("No security threats detected", size=14, color="#64748B", weight=ft.FontWeight.W_500),
                ft.Text("Click 'Start Monitoring' for live raw sniffing or 'Replay PCAP' for attack simulation", size=12, color="#475569"),
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
            alignment=ft.Alignment(0, 0), padding=30,
        )

        self.feed_container = ft.Container(
            content=self.empty_state,
            expand=True, bgcolor="#0B0F19",
            border=ft.Border.all(1, "#1F2937"), border_radius=10, padding=10,
        )

        # Main Page Assembly
        self.page.add(
            header,
            ft.Divider(color="#1F2937", height=12),
            kpi_row,
            control_panel,
            ft.Row([
                ft.Text("Real-Time Incident Stream", size=15, weight=ft.FontWeight.BOLD, color="#F8FAFC"),
                ft.Text("(Deterministic Rules & Threat Intelligence)", size=12, color="#64748B"),
            ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            self.feed_container,
        )

    def _make_status_chip(self, label: str, fg_color: str, bg_color: str):
        return ft.Container(
            content=ft.Row([
                ft.Container(width=8, height=8, border_radius=4, bgcolor=fg_color),
                ft.Text(label, size=11, weight=ft.FontWeight.BOLD, color=fg_color),
            ], spacing=6),
            bgcolor=bg_color, padding=ft.Padding.symmetric(horizontal=10, vertical=4),
            border_radius=16,
        )

    # ---------------- session lifecycle ----------------
    def on_start(self, e):
        ctx = detect_network_context()
        self._update_network_context_ui(ctx)

        session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="live")
        self.session_id = session_id
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)
        if session_id is not None:
            self.seal_mgr = SealManager(self.db, session_id, CONFIG.seal.auto_restore_seconds)

        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self._set_status_chip("LIVE CAPTURE", "#10B981", "#064E3B")
        self.feed_container.content = self.alert_list
        self.page.update()

        capture = LiveCapture(ctx.interface, self._on_packet)
        self.live_capture = capture

        def _capture_worker():
            try:
                capture.start()
            except PermissionError:
                self._set_status_chip("PERMISSION ERROR", "#EF4444", "#7F1D1D")
                self.start_btn.disabled = False
                self.stop_btn.disabled = True
                self.page.update()
            except Exception as ex:
                self._set_status_chip("CAPTURE ERROR", "#EF4444", "#7F1D1D")
                self.start_btn.disabled = False
                self.stop_btn.disabled = True
                self.page.update()

        self.capture_thread = threading.Thread(target=_capture_worker, daemon=True)
        self.capture_thread.start()

    def on_stop(self, e):
        if self.live_capture:
            self.live_capture.stop()
        if self.session_id is not None:
            self.db.end_session(self.session_id)
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        self._set_status_chip("IDLE", "#64748B", "#1E293B")
        self.page.update()

    def on_replay(self, e):
        path = self.pcap_field.value.strip() or "sample_pcaps/demo_public_wifi.pcap"
        ctx = detect_network_context()
        effective_gw = self.gateway_field.value.strip() or ctx.gateway_ip

        session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source=path)
        self.session_id = session_id
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=effective_gw)
        if session_id is not None:
            self.seal_mgr = SealManager(self.db, session_id, CONFIG.seal.auto_restore_seconds)

        self._update_network_context_ui(ctx, override_gw=effective_gw)
        self._set_status_chip("REPLAYING PCAP", "#06B6D4", "#083344")
        self.feed_container.content = self.alert_list
        self.page.update()

        replay = PcapReplay(path, self._on_packet)

        def run():
            try:
                count = replay.run()
                self._set_status_chip(f"REPLAY COMPLETE ({count} pkts)", "#10B981", "#064E3B")
            except Exception as ex:
                self._set_status_chip("REPLAY ERROR", "#EF4444", "#7F1D1D")
            finally:
                if session_id is not None:
                    self.db.end_session(session_id)
                self.page.update()

        threading.Thread(target=run, daemon=True).start()

    def _update_network_context_ui(self, ctx, override_gw=None):
        profile = ctx.classification.upper()
        color = "#EF4444" if "PUBLIC" in profile else ("#10B981" if "TRUSTED" in profile else "#F59E0B")
        self.context_label.value = profile
        self.context_label.color = color
        self.ssid_label.value = f"SSID: {ctx.ssid or 'unnamed_network'}"
        self.iface_label.value = f"Interface: {ctx.interface or 'default'}"
        self.gateway_label.value = f"Gateway: {override_gw or ctx.gateway_ip or 'unknown'}"
        self.page.update()

    def _set_status_chip(self, label: str, fg_color: str, bg_color: str):
        self.status_chip_container.controls = [self._make_status_chip(label, fg_color, bg_color)]
        self.page.update()

    # ---------------- packet -> alert -> UI pipeline ----------------
    def _on_packet(self, packet):
        if self.engine is None or self.session_id is None:
            return
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

            # Fire native OS popup notification (works even when app is in background)
            send_desktop_notification(
                title=f"🚨 Arpie NIDS Alert: {alert.detection_type.replace('_', ' ').title()}",
                message=f"Threat from {alert.source_ip or 'unknown'} (Severity: {alert.severity.upper()}, Risk: +{score} pts). Open Arpie to Seal.",
                severity=alert.severity,
            )

        if alerts:
            overall = session_risk_score(self.alerts, self.enrichments)
            band = risk_band(overall)
            band_color = SEVERITY_COLORS.get(band.lower(), "#10B981")
            band_bg = SEVERITY_BG.get(band.lower(), "#064E3B")

            self.risk_score_text.value = str(overall)
            self.risk_score_text.color = band_color
            self.risk_progress.value = overall / 100
            self.risk_progress.color = band_color
            self.risk_band_text.value = band.upper()
            self.risk_band_text.color = band_color
            self.risk_band_badge.bgcolor = band_bg

            self.alerts_count_text.value = str(len(self.alerts))
            self.intel_hits_text.value = str(len(self.enrichments))
            self.page.update()

    def _render_alert(self, alert, score, event_id, enrichment):
        color = SEVERITY_COLORS.get(alert.severity, "#94A3B8")
        bg_chip = SEVERITY_BG.get(alert.severity, "#1E293B")

        enrichment_widget = ft.Container()
        if enrichment:
            enrichment_widget = ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.PUBLIC_ROUNDED, size=14, color="#38BDF8"),
                    ft.Text(
                        f"AbuseIPDB Score: {enrichment.abuse_confidence_score}% | {enrichment.country or 'Geo: ?'} | {enrichment.isp or 'ISP: ?'}",
                        size=11, color="#BAE6FD",
                    ),
                ], spacing=6),
                bgcolor="#0C4A6E", border_radius=4, padding=ft.Padding.symmetric(horizontal=8, vertical=3),
            )

        seal_btn = ft.ElevatedButton(
            "Enable Seal Mode", icon=ft.Icons.SHIELD_ROUNDED,
            on_click=lambda e, ip=alert.target, eid=event_id: self._confirm_seal(ip, eid),
            style=ft.ButtonStyle(
                bgcolor="#DC2626", color="#FFFFFF",
                shape=ft.RoundedRectangleBorder(radius=6),
                padding=ft.Padding.symmetric(horizontal=12, vertical=8),
            ),
        )

        card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Container(
                        content=ft.Text(alert.severity.upper(), color="#FFFFFF", size=10, weight=ft.FontWeight.BOLD),
                        bgcolor=bg_chip, border=ft.Border.all(1, color), padding=ft.Padding.symmetric(horizontal=8, vertical=2), border_radius=4,
                    ),
                    ft.Text(alert.detection_type.replace("_", " ").title(), size=14, weight=ft.FontWeight.BOLD, color="#F8FAFC"),
                    ft.Container(expand=True),
                    ft.Text(f"Confidence: {alert.confidence:.0%}", size=12, color="#94A3B8"),
                    ft.Text(f"Risk: +{score} pts", size=12, weight=ft.FontWeight.BOLD, color=color),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Row([
                    ft.Icon(ft.Icons.SWAP_HORIZ_ROUNDED, size=16, color="#64748B"),
                    ft.Text(f"Source: {alert.source_ip or 'unknown'}", size=12, color="#CBD5E1", weight=ft.FontWeight.W_500),
                    ft.Text("➔", size=12, color="#64748B"),
                    ft.Text(f"Target: {alert.target or 'host'}", size=12, color="#CBD5E1", weight=ft.FontWeight.W_500),
                ], spacing=6),
                ft.Container(
                    content=ft.Text(alert.evidence.get("reason", str(alert.evidence)), size=11, font_family="monospace", color="#E2E8F0"),
                    bgcolor="#0F172A", border=ft.Border.all(1, "#1E293B"), border_radius=4, padding=8,
                ),
                enrichment_widget,
                ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text(f"💡 Recommended: {alert.recommended_action}", size=11, italic=True, color="#94A3B8"),
                        seal_btn,
                    ],
                ),
            ], spacing=8),
            bgcolor="#111827",
            border=ft.Border(left=ft.BorderSide(4, color), top=ft.BorderSide(1, "#1F2937"), right=ft.BorderSide(1, "#1F2937"), bottom=ft.BorderSide(1, "#1F2937")),
            border_radius=8, padding=12,
        )
        self.alert_list.controls.append(card)
        self.page.update()

    # ---------------- Seal Mode confirmation ----------------
    def _confirm_seal(self, target_ip, event_id):
        def do_seal(e):
            self.page.pop_dialog()
            if self.seal_mgr is not None:
                result = self.seal_mgr.seal(target_ip, event_id, confirmed_by_user=True)
                if result.success and target_ip not in self.active_blocks:
                    self.active_blocks.append(target_ip)
                    self.blocks_count_text.value = str(len(self.active_blocks))
                self._set_status_chip(f"SEAL ACTIVE: {target_ip}", "#EF4444", "#7F1D1D")
            self.page.update()

        def cancel(e):
            self.page.pop_dialog()
            if self.session_id is not None:
                self.db.log_action(self.session_id, event_id, "dismiss", target_ip,
                                    confirmed_by_user=True, notes="User dismissed Seal Mode prompt")

        dlg = ft.AlertDialog(
            modal=True,
            title=ft.Row([
                ft.Icon(ft.Icons.SECURITY_ROUNDED, color="#EF4444", size=24),
                ft.Text("Confirm Seal Mode Activation", weight=ft.FontWeight.BOLD),
            ], spacing=8),
            content=ft.Container(
                content=ft.Column([
                    ft.Text(f"Apply a temporary kernel firewall drop rule targeting {target_ip}?", size=13),
                    ft.Container(
                        content=ft.Text(f"iptables -I INPUT -s {target_ip} -j DROP", size=11, font_family="monospace", color="#FCA5A5"),
                        bgcolor="#450A0A", padding=8, border_radius=4,
                    ),
                    ft.Text(f"• Reversible: Auto-restores in {CONFIG.seal.auto_restore_seconds // 60} minutes.\n• Audit-logged to SQLite for end-of-session forensics.", size=12, color="#94A3B8"),
                ], spacing=10),
                width=420,
            ),
            actions=[
                ft.TextButton("Dismiss", on_click=cancel),
                ft.ElevatedButton("Confirm & Seal", icon=ft.Icons.LOCK_ROUNDED, on_click=do_seal, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF")),
            ],
        )
        self.page.show_dialog(dlg)

    # ---------------- report export ----------------
    def on_export(self, fmt: str):
        if not self.session_id:
            self._set_status_chip("NO SESSION TO EXPORT", "#F59E0B", "#78350F")
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
        self._set_status_chip(f"EXPORTED: {out_path}", "#10B981", "#064E3B")
        self.page.update()


def main(page: ft.Page):
    ArpieApp(page)


def run():
    ft.run(main)
