import datetime
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

        self.current_screen = "register" if not self.db.has_operators() else "login"
        self.current_view = "dashboard"

        self.user_role = "End User"
        self.user_name = ""

        self.network_context: Optional[NetworkContext] = None
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
        }

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
        self.content_area = ft.Container(expand=True, bgcolor="#F8FAFC", padding=20)
        self.top_bar_title = ft.Text("Dashboard", size=20, weight=ft.FontWeight.BOLD, color="#0F172A")
        self.top_bar_subtitle = ft.Text("Real-time overview of your network and security status", size=12, color="#64748B")

        self.root_container = ft.Container(expand=True, bgcolor="#F8FAFC")

        self._init_page()
        self.page.add(self.root_container)
        self.render()
        self.page.run_task(self._timer_task)

    def _init_page(self):
        self.page.title = "Arpie — Endpoint NIDS & Threat Response"
        self.page.theme_mode = ft.ThemeMode.LIGHT
        self.page.bgcolor = "#F8FAFC"
        self.page.padding = 0
        self.page.spacing = 0
        self.page.window.width = 1280
        self.page.window.height = 756
        self.page.window.min_width = 1100
        self.page.window.min_height = 700
        self.file_picker = ft.FilePicker()
        self.page.services.append(self.file_picker)
