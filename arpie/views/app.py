import datetime
import json
import os
import threading
from typing import Optional

import flet as ft

from arpie.infrastructure.capture import LiveCapture
from arpie.config import CONFIG
from arpie.models import Database
from arpie.detection import Alert, DetectionEngine
from arpie.network.context import NetworkContext
from arpie.security import SealManager
from arpie.infrastructure.threat_intel import IpEnrichment, ThreatIntelClient
from arpie.network import detect_network_context, local_ipv4_and_cidr
from arpie.detection import session_risk_score
from arpie.controllers import AuthController, CaptureController, ReportController, SealController
from arpie.views.mixins import (
    AuthMixin,
    MonitoringMixin,
    NavigationMixin,
    ReportsMixin,
    SealMixin,
    SessionRestoreMixin,
)


class ArpieApp(NavigationMixin, MonitoringMixin, SessionRestoreMixin, AuthMixin, ReportsMixin, SealMixin):
    def __init__(self, page: ft.Page):
        self.page = page
        self.db = Database(CONFIG.db_path)
        self.threat_intel = ThreatIntelClient(self.db, CONFIG.threat_intel)

        self.current_screen = "login" if self.db.has_operators() else "register"
        self.current_view = "dashboard"

        self.user_role = "End User"
        self.user_name = ""

        self.network_context: Optional[NetworkContext] = None
        self.local_ip: Optional[str] = None
        self.subnet_cidr: Optional[str] = None
        try:
            self.refresh_network_context()
        except Exception:
            pass
        self.selected_profile = "Public Wi-Fi"
        self.detection_rules = {
            "arp": True,
            "port_scan": True,
            "traffic_rate": True,
            "gateway": True,
        }
        self.thresholds = {
            "traffic": "100",
            "port": "15",
            "arp_window": "5",
            "gw_window": "10",
        }
        for key, default in self.thresholds.items():
            self.thresholds[key] = self.db.get_config(f"detection_threshold_{key}", default)
        for key, default in self.detection_rules.items():
            saved = self.db.get_config(f"detection_rule_{key}", "" if default else "0")
            if saved:
                self.detection_rules[key] = saved == "1"

        self.selected_alert: Optional[dict] = None
        self.session_id: Optional[int] = None
        self.engine: Optional[DetectionEngine] = None
        self.seal_mgr: Optional[SealManager] = None
        self.live_capture: Optional[LiveCapture] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.capture_controller = CaptureController(self)
        self.auth_controller = AuthController(self)
        self.report_controller = ReportController(self)
        self.seal_controller = SealController(self)

        self.is_monitoring = False
        self.monitoring_start_time: Optional[float] = None
        self.accumulated_seconds = 0.0
        self.last_resume_time = 0.0
        self.timer_thread: Optional[threading.Thread] = None
        self.timer_running = False

        self.operator_id: Optional[int] = None
        self.operator_username = ""
        self.operator_email = ""
        self.operator_last_login = ""
        self._pending_operator: Optional[dict] = None

        self.alerts: list[Alert] = []
        self.enrichments: dict[str, IpEnrichment] = {}
        self.active_blocks: list[str] = []
        self.packets_count = 0

        self.all_alerts_list = []

        self.top_talkers_data = []
        self._ip_packet_counts: dict[str, int] = {}

        self.devices_inventory = []
        self._known_device_macs: set[str] = set()

        self.packet_log_stream = []

        self.traffic_interval_sec = 5
        self.traffic_history = [0] * 12
        self.suspicious_history = [0] * 12
        self.blocked_history = [0] * 12
        init_time = datetime.datetime.now()
        self.traffic_timestamps = [
            (init_time - datetime.timedelta(seconds=(11 - i) * self.traffic_interval_sec)).strftime("%H:%M:%S")
            for i in range(12)
        ]
        self._current_interval_total = 0
        self._current_interval_suspicious = 0
        self._current_interval_blocked = 0
        self._tick_counter = 0
        self.dashboard_chart_slot = None

        self.active_severity_filter = "All"
        self.search_query = ""
        self.status_toast = ""

        from pathlib import Path
        custom_export = (CONFIG.export_dir or "").strip()
        saved_dir = (self.db.get_config("reports_dir", "") or "").strip()
        if custom_export:
            target_dir = Path(custom_export).expanduser()
        elif saved_dir:
            target_dir = Path(saved_dir).expanduser()
        else:
            docs_path = Path.home() / "Documents"
            target_dir = (docs_path / "Arpie_Reports") if (docs_path.exists() and docs_path.is_dir()) else (Path.home() / "Arpie_Reports")
        self.reports_dir = target_dir
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        self.timer_text = ft.Text("00:00:00", size=24, weight=ft.FontWeight.BOLD, color="#0F172A")
        self.sidebar_timer_text = ft.Text("00:00:00", size=16, weight=ft.FontWeight.BOLD, color="#FFFFFF")
        self.sidebar_status_dot = ft.Container(width=6, height=6, border_radius=3, bgcolor="#64748B")
        self.sidebar_status_text = ft.Text("PAUSED", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8")
        self.sidebar_btn_icon = ft.Icon(ft.Icons.PLAY_ARROW_ROUNDED, color="#FFFFFF", size=16)
        self.sidebar_btn_text = ft.Text("Resume", size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF")
        self.sidebar_toggle_btn = ft.Button(
            content=ft.Row([self.sidebar_btn_icon, self.sidebar_btn_text], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
            style=ft.ButtonStyle(
                bgcolor="#10B981",
                shape=ft.RoundedRectangleBorder(radius=6),
            ),
            on_click=lambda e: self.toggle_monitoring(),
            width=200,
        )

        self.sidebar_btn_refs = []
        self.sidebar_badge_refs = {}
        self.content_area = ft.Container(expand=True, bgcolor="#F8FAFC", padding=20)
        # Persistent global toast, shown above whatever page is active so
        # action feedback (e.g. Seal Mode results) is visible no matter
        # which view the user confirmed the action from.
        self.toast_text = ft.Text("", size=13, color="#0F172A", expand=True)
        self.toast_icon = ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED, color="#10B981", size=18)
        self.toast_banner = ft.Container(
            content=ft.Row([self.toast_icon, self.toast_text], spacing=8),
            padding=12, border_radius=8, margin=ft.Margin.only(left=20, right=20, top=12),
            visible=False,
        )
        self.top_bar_title = ft.Text("Dashboard", size=20, weight=ft.FontWeight.BOLD, color="#0F172A")
        self.top_bar_subtitle = ft.Text("Real-time overview of your network and security status", size=12, color="#64748B")

        self.root_container = ft.Container(expand=True, bgcolor="#F8FAFC")

        self._init_page()
        self.page.add(self.root_container)
        self.render()
        self.page.run_task(self._timer_task)

    def get_trusted_ssids(self) -> list[str]:
        try:
            values = json.loads(self.db.get_config("network.trusted_ssids", "[]"))
            return [value for value in values if isinstance(value, str)]
        except (TypeError, ValueError):
            return []

    def refresh_network_context(self):
        saved_iface = self.db.get_config("network.interface", "")
        if saved_iface and not os.environ.get("ARPIE_IFACE"):
            os.environ["ARPIE_IFACE"] = saved_iface
        self.network_context = detect_network_context(self.get_trusted_ssids())
        self.local_ip, self.subnet_cidr = local_ipv4_and_cidr(self.network_context.interface)
        if not self.local_ip:
            self.local_ip, self.subnet_cidr = local_ipv4_and_cidr(None)
        return self.network_context

    def ensure_host_ip(self) -> Optional[str]:
        if not self.local_ip:
            try:
                self.refresh_network_context()
            except Exception:
                pass
        return self.local_ip

    def apply_classification(self, radio_value: str, remember: bool = False):
        mapping = {"public": "public-untrusted", "trusted": "trusted", "unknown": "unknown"}
        ctx = self.network_context or self.refresh_network_context()
        if ctx is None:
            return
        ctx.classification = mapping.get(radio_value, "public-untrusted")
        ssid = ctx.ssid
        trusted = self.get_trusted_ssids()
        if ctx.classification == "trusted" and remember and ssid and ssid not in trusted:
            trusted.append(ssid)
        elif ctx.classification != "trusted" and ssid:
            trusted = [value for value in trusted if value != ssid]
        self.db.set_config("network.trusted_ssids", json.dumps(trusted))
        ctx.known_trusted_ssids = trusted


    @property
    def session_risk(self) -> int:
        if self.alerts:
            return session_risk_score(self.alerts, self.enrichments)
        return 0

    def simulate_demo_threat(self):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import ARP, Ether

        if self.engine is None:
            ctx = self.network_context or self.refresh_network_context()
            self.session_id = self.session_id or self.db.start_session(
                ctx.ssid, ctx.classification, ctx.interface, source="self-test", operator_id=self.operator_id
            )
            self.engine = self._configured_detection_engine(gateway_ip=ctx.gateway_ip)

        gateway = (self.network_context.gateway_ip if self.network_context else None) or "192.0.2.1"
        victim = self.local_ip or "192.0.2.10"
        attacker = "192.0.2.66"
        self.status_toast = "Self-test running: injecting synthetic attack packets through the detection engine."

        def inject():
            self._process_packet(Ether() / ARP(op=2, psrc=gateway, hwsrc="de:ad:be:ef:00:01", pdst=victim))
            self._process_packet(Ether() / ARP(op=2, psrc=gateway, hwsrc="de:ad:be:ef:00:02", pdst=victim))
            for port in range(20, 45):
                self._process_packet(Ether() / IP(src=attacker, dst=victim) / TCP(dport=port, flags="S"))
            for _ in range(160):
                self._process_packet(Ether() / IP(src=attacker, dst=victim) / TCP(dport=80, flags="S"))

        threading.Thread(target=inject, daemon=True).start()

    def _init_page(self):
        self.page.title = "Arpie — Endpoint NIDS & Threat Response"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = "#F8FAFC"
        self.page.padding = 0
        self.page.spacing = 0
        self.page.window.width = 1440
        self.page.window.height = 800
        self.page.window.min_width = 1280
        self.page.window.min_height = 700
        self.file_picker = ft.FilePicker()
        if hasattr(self.page, "services"):
            self.page.services.append(self.file_picker)
        elif hasattr(self.page, "overlay"):
            self.page.overlay.append(self.file_picker)

