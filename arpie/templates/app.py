import asyncio
import datetime
import json

import threading
import time
from typing import Optional

import flet as ft

from ..infrastructure.capture import LiveCapture
from ..config import CONFIG
from ..models import Database
from ..detection import Alert, DetectionEngine
from ..network import detect_network_context
from ..infrastructure import send_desktop_notification
from ..reporting import build_report_data, export_html, export_json, export_pdf
from ..domain import risk_band, score_alert, session_risk_score
from ..security import SealManager
from ..integrations import IpEnrichment, ThreatIntelClient
from ..controllers import AuthController, CaptureController, ReportController, SealController
from .components.sidebar import build_sidebar
from .components.topbar import build_topbar
from .theme import SEVERITY_BG, SEVERITY_COLORS
from ..views.alerts import render_alerts_view
from ..views.context import render_context_screen
from ..views.dashboard import render_dashboard_view
from ..views.inventory import render_inventory_view
from ..views.login import render_login_screen
from ..views.mfa import render_mfa_challenge_screen
from ..views.packets import render_packets_view
from ..views.profile import render_profile_screen
from ..views.register import render_register_screen
from ..views.reports import render_reports_view
from ..views.seal import render_seal_view
from ..views.settings import render_settings_view
from ..views.users import render_users_view


class ArpieApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.db = Database(CONFIG.db_path)
        self.threat_intel = ThreatIntelClient(self.db, CONFIG.threat_intel)

        self.current_screen = "register" if not self.db.has_operators() else "login"
        self.current_view = "dashboard"

        self.user_role = "End User"
        self.user_name = ""

        self.network_context = None
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
        self.monitoring_start_time = None
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
        self.sidebar_toggle_btn = ft.ElevatedButton(
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



    def render(self):
        if self.current_screen == "register":
            self.root_container.content = render_register_screen(self)
        elif self.current_screen == "login":
            self.root_container.content = render_login_screen(self)
        elif self.current_screen == "mfa_challenge":
            self.root_container.content = render_mfa_challenge_screen(self)
        elif self.current_screen == "context":
            self.root_container.content = render_context_screen(self)
        elif self.current_screen == "profile":
            self.root_container.content = render_profile_screen(self)
        elif self.current_screen == "app_shell":
            if not self.all_alerts_list and not self.devices_inventory:
                self._restore_session_from_db()
            self.root_container.content = self._build_app_shell()
            self.update_view_content()
        self.page.update()

    def go_to_context(self):
        self.current_screen = "context"
        self.render()

    def _build_app_shell(self):
        sidebar = build_sidebar(self)
        top_bar = build_topbar(self)

        main_area = ft.Container(
            content=ft.Column([
                top_bar,
                self.content_area,
            ], spacing=0, expand=True),
            expand=True,
            bgcolor="#F8FAFC",
        )

        return ft.Row([sidebar, main_area], expand=True, spacing=0)

    def nav_to(self, vid: str):
        self.current_view = vid
        self.update_view_content()
        self.page.update()

    def update_view_content(self):
        title_map = {
            "dashboard": ("Dashboard", "Real-time overview of your network and security status"),
            "alerts": ("Alerts", "All detected security events for this monitoring session"),
            "inventory": ("Network", "Network context assessment and discovered device inventory"),
            "packets": ("Packet Capture Logs", "Live inspection and recorded packet stream replay"),
            "seal": ("Seal Mode Mitigation", "Reversible endpoint threat response and network isolation"),
            "reports": ("Forensic Reports", "Automated incident reports, threat summaries, and exports"),
            "users": ("User Accounts", "Registered system operators and RBAC role assignments"),
            "settings": ("System Configuration", "Heuristic thresholds, threat intel feeds, and rules"),
        }
        title, subtitle = title_map.get(self.current_view, ("Arpie", ""))
        self.top_bar_title.value = title
        self.top_bar_subtitle.value = subtitle

        for vid, btn, icon_ctrl, text_ctrl, icon_on, icon_off in self.sidebar_btn_refs:
            is_active = (self.current_view == vid)
            btn.bgcolor = "#1E293B" if is_active else "transparent"
            icon_ctrl.name = icon_on if is_active else icon_off
            icon_ctrl.color = "#FFFFFF" if is_active else "#94A3B8"
            text_ctrl.color = "#FFFFFF" if is_active else "#94A3B8"
            text_ctrl.weight = ft.FontWeight.W_600 if is_active else ft.FontWeight.W_500

        view_map = {
            "dashboard": render_dashboard_view,
            "alerts": render_alerts_view,
            "inventory": render_inventory_view,
            "packets": render_packets_view,
            "seal": render_seal_view,
            "reports": render_reports_view,
            "users": render_users_view,
            "settings": render_settings_view,
        }
        render_fn = view_map.get(self.current_view)
        if render_fn:
            try:
                self.content_area.content = render_fn(self)
            except Exception as exc:
                import traceback
                traceback.print_exc()
                self.content_area.content = ft.Column([
                    ft.Icon(ft.Icons.ERROR_OUTLINE_ROUNDED, color="#DC2626", size=48),
                    ft.Text(f"Render error: {exc}", size=14, color="#DC2626"),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, alignment=ft.MainAxisAlignment.CENTER, expand=True)

    def update_monitoring_ui(self):
        is_mon = self.is_monitoring
        self.sidebar_status_dot.bgcolor = "#10B981" if is_mon else "#64748B"
        self.sidebar_status_text.value = "ACTIVE" if is_mon else "PAUSED"
        self.sidebar_status_text.color = "#10B981" if is_mon else "#94A3B8"
        self.sidebar_btn_icon.icon = ft.Icons.STOP_ROUNDED if is_mon else ft.Icons.PLAY_ARROW_ROUNDED
        self.sidebar_btn_text.value = "Stop Monitoring" if is_mon else "Resume"
        self.sidebar_toggle_btn.style = ft.ButtonStyle(
            bgcolor="#DC2626" if is_mon else "#10B981",
            shape=ft.RoundedRectangleBorder(radius=6),
        )
        try:
            if self.sidebar_status_dot.page is not None:
                self.sidebar_status_dot.update()
            if self.sidebar_status_text.page is not None:
                self.sidebar_status_text.update()
            if self.sidebar_toggle_btn.page is not None:
                self.sidebar_toggle_btn.update()
        except Exception:
            pass

    def logout(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.timer_running = False
        self.accumulated_seconds = 0.0
        self.last_resume_time = 0.0
        self.timer_text.value = "00:00:00"
        self.sidebar_timer_text.value = "00:00:00"
        self.update_monitoring_ui()
        if self.live_capture:
            try:
                self.live_capture.stop()
            except Exception:
                pass
            self.live_capture = None
        if self.session_id:
            try:
                self.db.end_session(self.session_id)
            except Exception:
                pass
            self.session_id = None
        self.operator_id = None
        self.operator_username = ""
        self.operator_email = ""
        self.user_name = ""
        self.user_role = "End User"
        self.status_toast = ""
        self._pending_operator = None
        self.current_screen = "login"
        self.render()

    def verify_mfa_login(self, code: str) -> tuple[bool, str]:
        return self.auth_controller.verify_mfa_login(code)

    def cancel_mfa_login(self):
        self.auth_controller.cancel_mfa_login()

    def _complete_login(self, operator: dict):
        self.auth_controller.complete_login(operator)

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

    def set_traffic_interval(self, sec: int):
        self.traffic_interval_sec = max(1, sec)
        self._tick_counter = 0
        if self.current_view == "dashboard":
            slot = getattr(self, "dashboard_chart_slot", None)
            if slot and getattr(slot, "page", None):
                try:
                    from ..views.dashboard import _build_spline_chart_content
                    slot.content = _build_spline_chart_content(self)
                    slot.update()
                    return
                except Exception:
                    pass
            self.update_view_content()
            if self.page:
                self.page.update()

    def enable_totp(self, username: str) -> tuple[str, list[str]]:
        from ..middleware.mfa import generate_secret, generate_recovery_codes
        secret = generate_secret()
        codes = generate_recovery_codes(8)
        self.db.set_totp_secret(username, secret)
        self.db.set_recovery_codes(username, codes)
        return secret, codes

    def disable_totp(self, username: str):
        self.db.set_totp_secret(username, None)
        self.db.set_recovery_codes(username, None)

    def set_severity_filter(self, label: str):
        self.active_severity_filter = label
        self.update_view_content()
        self.page.update()

    def on_search_change(self, val: str):
        self.search_query = val
        self.update_view_content()
        self.page.update()

    @property
    def is_evaluator(self) -> bool:
        return self.user_role == "Evaluator/Administrator"

    def toggle_rule(self, k: str, val: bool):
        if not self.is_evaluator:
            return
        self.detection_rules[k] = val

    def set_threshold(self, k: str, val: str):
        if not self.is_evaluator:
            return
        self.thresholds[k] = val

    def open_dialog(self, dlg: ft.AlertDialog):
        self.page.show_dialog(dlg)

    def close_dialog(self, dlg: ft.AlertDialog):
        self.page.pop_dialog()

    def activate_seal(self, dlg):
        self.seal_controller.activate(dlg)

    def block_ip(self, ip: str, dlg):
        self.seal_controller.block_ip(ip, dlg)

    def unblock_ip(self, ip: str):
        self.seal_controller.unblock_ip(ip)

    def save_operator_credentials(self, username: str, current_pw: str, new_pw: str) -> tuple[bool, str]:
        username = (username or "").strip()
        if not username:
            return False, "Operator username cannot be empty."

        operator = self.db.authenticate_operator(self.operator_username, current_pw)
        if not operator:
            return False, "Current password verification failed."

        if new_pw:
            if len(new_pw) < 4:
                return False, "New password must be at least 4 characters."
            self.db.update_operator_password(self.operator_username, new_pw)

        if username != self.operator_username:
            existing = self.db.get_operator(username)
            if existing:
                return False, f"Username '{username}' is already taken."

        self.db.update_operator_display_name(self.operator_username, username)
        self.operator_username = username
        self.user_name = username
        return True, f"Operator credentials for '{username}' updated successfully."


    def _process_packet(self, packet):
        self.packets_count += 1
        self._current_interval_total += 1

        src_ip = "Unknown"
        dst_ip = "Unknown"
        proto = "OTHER"
        src_mac = "Unknown"
        dst_mac = "Unknown"
        pkt_len = str(len(packet))

        try:
            if hasattr(packet, "src"):
                src_mac = str(packet.src)
            if hasattr(packet, "dst"):
                dst_mac = str(packet.dst)

            if packet.haslayer("ARP"):
                proto = "ARP"
                arp_layer = packet.getlayer("ARP")
                src_ip = arp_layer.psrc
                dst_ip = arp_layer.pdst
            elif packet.haslayer("IP"):
                ip_layer = packet.getlayer("IP")
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                if packet.haslayer("TCP"):
                    tcp = packet.getlayer("TCP")
                    proto = f"TCP ({tcp.dport})" if tcp.flags == "S" else "TCP"
                elif packet.haslayer("UDP"):
                    proto = "UDP"
                elif packet.haslayer("ICMP"):
                    proto = "ICMP"
                else:
                    proto = "IP"

            if src_ip in self.active_blocks or dst_ip in self.active_blocks:
                self._current_interval_blocked += 1

            self.packet_log_stream.insert(0, {
                "ts": datetime.datetime.now().strftime("%H:%M:%S.%f")[:12],
                "src": src_ip,
                "dst": dst_ip,
                "proto": proto,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "len": pkt_len,
            })
            if len(self.packet_log_stream) > 200:
                self.packet_log_stream.pop()

            if src_ip != "Unknown":
                self._ip_packet_counts[src_ip] = self._ip_packet_counts.get(src_ip, 0) + 1
            if dst_ip != "Unknown":
                self._ip_packet_counts[dst_ip] = self._ip_packet_counts.get(dst_ip, 0) + 1
            self._rebuild_top_talkers()

            self._passive_discover_device(src_ip, src_mac)
        except Exception:
            pass

        if self.engine:
            for alert in self.engine.process(packet):
                self._current_interval_suspicious += 1
                alert_dict = {
                    "time": datetime.datetime.now().strftime("%H:%M:%S"),
                    "type": alert.detection_type.replace("_", " ").title(),
                    "severity": alert.severity.upper(),
                    "source": alert.source_ip or src_ip or "Unknown",
                    "status": "NEW",
                    "fg": SEVERITY_COLORS.get(alert.severity.lower(), "#DC2626"),
                    "bg": SEVERITY_BG.get(alert.severity.lower(), "#FEE2E2"),
                    "desc": str(alert.evidence),
                }
                self.all_alerts_list.insert(0, alert_dict)

                enrichment = None
                lookup_ip = alert.source_ip or src_ip
                if lookup_ip and self.threat_intel:
                    try:
                        enrichment = self.threat_intel.enrich(lookup_ip)
                        if enrichment:
                            self.enrichments[lookup_ip] = enrichment
                    except Exception:
                        pass

                if self.session_id:
                    score = score_alert(alert, enrichment)
                    self.db.log_event(
                        self.session_id,
                        alert.detection_type,
                        alert.source_ip or src_ip,
                        alert.target,
                        alert.severity,
                        alert.confidence,
                        score,
                        alert.evidence if isinstance(alert.evidence, dict) else {"raw": str(alert.evidence)},
                        alert.recommended_action,
                    )

                evidence_text = alert.evidence.get("reason", str(alert.evidence)) if isinstance(alert.evidence, dict) else str(alert.evidence)
                send_desktop_notification(
                    title=f"🚨 [{alert.severity}] {alert_dict['type']} Detected",
                    message=f"Host: {alert_dict['source']}\n{evidence_text}\n→ Action: {alert.recommended_action}",
                    severity=alert.severity.lower(),
                )

                try:
                    self.update_view_content()
                    if self.page:
                        self.page.update()
                except Exception:
                    pass

    def _rebuild_top_talkers(self):
        sorted_ips = sorted(self._ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        total = sum(c for _, c in sorted_ips) or 1
        self.top_talkers_data = [
            {"ip": ip, "packets": count, "pct": f"{count / total * 100:.1f}%"}
            for ip, count in sorted_ips
        ]

    def _passive_discover_device(self, ip: str, mac: str):
        if not ip or ip == "Unknown" or not mac or mac == "Unknown" or ip == "0.0.0.0":
            return
        mac_lower = mac.lower()
        if mac_lower in self._known_device_macs:
            return
        self._known_device_macs.add(mac_lower)
        from ..network import mac_vendor
        vendor = mac_vendor(mac)
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        ctx = self.network_context
        gw_ip = ctx.gateway_ip if ctx else None
        if ip == gw_ip:
            status = "Active Gateway"
            dev_type = "Gateway / Router"
            hostname = "Gateway"
        else:
            status = "Discovered"
            dev_type = "Endpoint"
            hostname = f"Host-{ip.split('.')[-1]}"
        self.devices_inventory.append({
            "id": str(len(self.devices_inventory) + 1),
            "hostname": hostname,
            "ip": ip,
            "mac": mac_lower,
            "vendor": vendor,
            "type": dev_type,
            "status": status,
            "last_seen": now,
        })

    def start_monitoring(self):
        self.is_monitoring = True
        self.accumulated_seconds = 0.0
        self.last_resume_time = time.time()
        self.monitoring_start_time = self.last_resume_time

        self._ip_packet_counts.clear()
        self._current_interval_total = 0
        self._current_interval_suspicious = 0
        self._current_interval_blocked = 0
        self._tick_counter = 0

        ctx = detect_network_context()
        self.network_context = ctx
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="live", operator_id=self.operator_id)
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)

        threading.Thread(target=self._initial_arp_sweep, args=(ctx,), daemon=True).start()

        if not self.live_capture:
            self.live_capture = LiveCapture(interface=ctx.interface or "wlan0", on_packet=self._process_packet)
            self.capture_thread = threading.Thread(target=self._start_capture_safe, daemon=True)
            self.capture_thread.start()

        self.update_monitoring_ui()

    def _initial_arp_sweep(self, ctx):
        from ..network import arp_sweep, mac_vendor, local_ipv4_and_cidr
        try:
            _, cidr = local_ipv4_and_cidr(ctx.interface if ctx else None)
            if not cidr:
                return
            hosts = arp_sweep(cidr, iface=ctx.interface if ctx else None, timeout=3)
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            for h in hosts:
                mac_lower = h["mac"].lower()
                if mac_lower not in self._known_device_macs:
                    self._known_device_macs.add(mac_lower)
                    vendor = mac_vendor(h["mac"])
                    gw_ip = ctx.gateway_ip if ctx else None
                    if h["ip"] == gw_ip:
                        status = "Active Gateway"
                        dev_type = "Gateway / Router"
                        hostname = "Gateway"
                    else:
                        status = "Discovered"
                        dev_type = "Endpoint"
                        hostname = f"Host-{h['ip'].split('.')[-1]}"
                    self.devices_inventory.append({
                        "id": str(len(self.devices_inventory) + 1),
                        "hostname": hostname,
                        "ip": h["ip"],
                        "mac": mac_lower,
                        "vendor": vendor,
                        "type": dev_type,
                        "status": status,
                        "last_seen": now,
                    })
            try:
                self.update_view_content()
                if self.page:
                    self.page.update()
            except Exception:
                pass
        except Exception:
            pass

    def _start_capture_safe(self):
        try:
            if self.live_capture:
                self.live_capture.start()
        except Exception as e:
            self.status_toast = f"Live sniffing notice: {e}"

    def toggle_monitoring(self):
        self.is_monitoring = not self.is_monitoring
        if not self.is_monitoring:
            if self.last_resume_time > 0:
                self.accumulated_seconds += time.time() - self.last_resume_time
                self.last_resume_time = 0.0
            if self.live_capture:
                self.live_capture.stop()
                self.live_capture = None
        else:
            self.last_resume_time = time.time()
            if not self.live_capture:
                ctx = self.network_context or detect_network_context()
                self.live_capture = LiveCapture(interface=ctx.interface or "wlan0", on_packet=self._process_packet)
                self.capture_thread = threading.Thread(target=self._start_capture_safe, daemon=True)
                self.capture_thread.start()
        self.update_monitoring_ui()
        self.update_view_content()
        self.page.update()

    async def _timer_task(self):
        poll_count = 0
        while True:
            await asyncio.sleep(1)
            poll_count += 1
            if poll_count >= 2:
                poll_count = 0
                if self.current_screen == "app_shell":
                    latest = self.db.get_latest_session(self.operator_id)
                    current_sid = latest["id"] if latest else None
                    if current_sid != self.session_id:
                        if latest:
                            self._restore_session_from_db()
                        else:
                            self.session_id = None
                            self.all_alerts_list = []
                            self.devices_inventory = []
                            self.packets_count = 0
                            self.traffic_history = [0] * 12
                            self.top_talkers_data = []
                            self.threats_count = 0
                        self.update_view_content()
                        if self.page:
                            self.page.update()

            if self.is_monitoring and self.last_resume_time > 0 and self.current_screen == "app_shell":
                elapsed = int(self.accumulated_seconds + (time.time() - self.last_resume_time))
                hrs = elapsed // 3600
                mins = (elapsed % 3600) // 60
                secs = elapsed % 60
                timestr = f"{hrs:02d}:{mins:02d}:{secs:02d}"
                self.timer_text.value = timestr
                self.sidebar_timer_text.value = timestr

                self._tick_counter += 1
                interval_limit = max(1, getattr(self, "traffic_interval_sec", 1))
                if self._tick_counter >= interval_limit:
                    self._tick_counter = 0
                    now_ts = datetime.datetime.now().strftime("%H:%M:%S")

                    rate_total = round(self._current_interval_total / interval_limit)
                    rate_susp = round(self._current_interval_suspicious / interval_limit)
                    rate_blocked = round(self._current_interval_blocked / interval_limit)

                    self.traffic_history.append(rate_total)
                    self.suspicious_history.append(rate_susp)
                    self.blocked_history.append(rate_blocked)
                    self.traffic_timestamps.append(now_ts)

                    while len(self.traffic_history) > 12:
                        self.traffic_history.pop(0)
                    while len(self.suspicious_history) > 12:
                        self.suspicious_history.pop(0)
                    while len(self.blocked_history) > 12:
                        self.blocked_history.pop(0)
                    while len(self.traffic_timestamps) > 12:
                        self.traffic_timestamps.pop(0)

                    self._current_interval_total = 0
                    self._current_interval_suspicious = 0
                    self._current_interval_blocked = 0

                    if self.current_view == "dashboard":
                        slot = getattr(self, "dashboard_chart_slot", None)
                        if slot and getattr(slot, "page", None):
                            try:
                                from ..views.dashboard import _build_spline_chart_content
                                slot.content = _build_spline_chart_content(self)
                                slot.update()
                            except Exception:
                                self.update_view_content()
                        else:
                            self.update_view_content()

                try:
                    if self.page:
                        self.page.update()
                except Exception:
                    pass


    def run_pcap_replay(self, pcap_path: str):
        self.capture_controller.run_pcap_replay(pcap_path)


    def set_reports_dir(self, path_str: str) -> tuple[bool, str]:
        from pathlib import Path
        cleaned = path_str.strip()
        if not cleaned:
            return False, "Export path cannot be empty."
        try:
            target = Path(cleaned).expanduser().resolve()
            target.mkdir(parents=True, exist_ok=True)
            self.reports_dir = target
            self.db.set_config("reports_dir", str(target))
            self.status_toast = f"Export directory updated to: {target}"
            self.update_view_content()
            self.page.update()
            return True, str(target)
        except Exception as ex:
            return False, str(ex)

    def open_reports_directory(self):
        import platform
        import subprocess
        system = platform.system()
        path = str(self.reports_dir)
        try:
            if system == "Linux":
                subprocess.Popen(["xdg-open", path])
            elif system == "Darwin":
                subprocess.Popen(["open", path])
            elif system == "Windows":
                subprocess.Popen(["explorer", path])
        except Exception:
            pass

    def pick_reports_directory(self):
        async def _pick():
            try:
                chosen = await self.file_picker.get_directory_path(
                    dialog_title="Select Report Export Directory",
                    initial_directory=str(self.reports_dir),
                )
                if chosen:
                    self.set_reports_dir(chosen)
            except Exception as ex:
                self.status_toast = f"Folder picker error: {ex}"
                self.update_view_content()
                self.page.update()

        self.page.run_task(_pick)

    def export_report(self, fmt: str, target_session_id: Optional[int] = None):
        self.report_controller.export(fmt, target_session_id)
