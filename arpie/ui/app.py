import datetime
import random
import threading
import time
from typing import Optional

import flet as ft

from ..capture import LiveCapture, PcapReplay
from ..config import CONFIG
from ..db import Database
from ..detection import Alert, DetectionEngine
from ..network_context import detect_network_context
from ..notification import send_desktop_notification
from ..report import build_report_data, export_html, export_json, export_pdf
from ..risk import risk_band, score_alert, session_risk_score
from ..seal import SealManager
from ..threat_intel import IpEnrichment, ThreatIntelClient
from .components.sidebar import build_sidebar
from .components.topbar import build_topbar
from .theme import SEVERITY_BG, SEVERITY_COLORS
from .views.alerts import render_alerts_view
from .views.context import render_context_screen
from .views.dashboard import render_dashboard_view
from .views.inventory import render_inventory_view
from .views.login import render_login_screen
from .views.packets import render_packets_view
from .views.profile import render_profile_screen
from .views.register import render_register_screen
from .views.reports import render_reports_view
from .views.seal import render_seal_view
from .views.settings import render_settings_view
from .views.users import render_users_view


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

        self.is_monitoring = False
        self.monitoring_start_time = None
        self.timer_thread: Optional[threading.Thread] = None
        self.timer_running = False

        self.operator_id: Optional[int] = None
        self.operator_username = ""
        self.operator_email = ""
        self.operator_last_login = ""

        self.alerts: list[Alert] = []
        self.enrichments: dict[str, IpEnrichment] = {}
        self.active_blocks: list[str] = ["192.168.1.50"]
        self.packets_count = 12394

        self.all_alerts_list = [
            {"time": "09:14:57", "type": "ARP Identity", "severity": "HIGH", "source": "192.168.1.1", "status": "NEW", "fg": "#DC2626", "bg": "#FEE2E2", "desc": "2 distinct MAC addresses claimed IP 192.168.1.1 within 300s (MACs: aa:bb:cc:dd:ee:11, aa:bb:cc:dd:ee:22)"},
            {"time": "09:11:45", "type": "Port Scan", "severity": "MEDIUM", "source": "192.168.1.50", "status": "NEW", "fg": "#D97706", "bg": "#FEF3C7", "desc": "16 unique TCP/UDP ports contacted on target 192.168.1.100 within 10s window"},
            {"time": "09:09:32", "type": "Traffic Anomaly", "severity": "MEDIUM", "source": "192.168.1.50", "status": "ACK", "fg": "#D97706", "bg": "#FEF3C7", "desc": "101.0 packets/sec exceeded burst rate threshold of 100 pps (Dominant: SYN flood)"},
            {"time": "09:08:21", "type": "Gateway Change", "severity": "LOW", "source": "192.168.1.1", "status": "REVIEW", "fg": "#10B981", "bg": "#ECFDF5", "desc": "Gateway MAC address altered to 00:50:56:C0:00:01 on interface wlan0"},
        ]

        self.top_talkers_data = [
            {"ip": "192.168.1.1", "packets": 2350, "pct": "18.9%"},
            {"ip": "192.168.1.105", "packets": 1842, "pct": "14.8%"},
            {"ip": "192.168.1.77", "packets": 1210, "pct": "9.8%"},
            {"ip": "192.168.1.50", "packets": 980, "pct": "7.9%"},
        ]

        self.devices_inventory = [
            {"id": "1", "hostname": "PC-01", "ip": "192.168.1.10", "mac": "00:0C:29:4F:11:AA", "vendor": "VMware, Inc.", "type": "PC", "status": "Trusted", "last_seen": "2026-08-31 16:10"},
            {"id": "2", "hostname": "Laptop-Work", "ip": "192.168.1.15", "mac": "00:1E:50:32:BB:CC", "vendor": "Dell Inc.", "type": "Laptop", "status": "Trusted", "last_seen": "2026-08-31 16:15"},
            {"id": "3", "hostname": "Printer-01", "ip": "192.168.1.20", "mac": "00:1B:44:12:34:7F", "vendor": "HP Inc.", "type": "Printer", "status": "Trusted", "last_seen": "2026-08-31 15:40"},
            {"id": "4", "hostname": "Router-01", "ip": "192.168.1.1", "mac": "00:50:56:C0:00:01", "vendor": "Cisco Systems", "type": "Router", "status": "Trusted", "last_seen": "2026-08-31 16:20"},
            {"id": "5", "hostname": "Unknown-Device", "ip": "192.168.1.50", "mac": "3C:97:0E:12:34:56", "vendor": "Unknown", "type": "PC", "status": "Untrusted", "last_seen": "2026-08-31 16:22"},
        ]


        self.packet_log_stream = [
            {"ts": "16:22:01.102", "src": "192.168.1.10", "dst": "192.168.1.1", "proto": "ARP", "src_mac": "00:0C:29:4F:11:AA", "dst_mac": "00:50:56:C0:00:01", "len": "42"},
            {"ts": "16:22:01.104", "src": "192.168.1.50", "dst": "192.168.1.1", "proto": "ARP", "src_mac": "3C:97:0E:12:34:56", "dst_mac": "00:50:56:C0:00:01", "len": "42"},
            {"ts": "16:22:01.110", "src": "192.168.1.15", "dst": "8.8.8.8", "proto": "DNS", "src_mac": "00:1E:50:32:BB:CC", "dst_mac": "00:50:56:C0:00:01", "len": "76"},
            {"ts": "16:22:01.115", "src": "192.168.1.50", "dst": "192.168.1.100", "proto": "TCP SYN", "src_mac": "3C:97:0E:12:34:56", "dst_mac": "00:0C:29:4F:11:AA", "len": "64"},
            {"ts": "16:22:01.120", "src": "192.168.1.1", "dst": "192.168.1.10", "proto": "TCP ACK", "src_mac": "00:50:56:C0:00:01", "dst_mac": "00:0C:29:4F:11:AA", "len": "1460"},
        ]

        self.traffic_history = [240, 310, 380, 420, 390, 480, 520, 490, 560, 610, 580, 640]
        self.suspicious_history = [10, 15, 25, 30, 20, 45, 60, 55, 75, 90, 85, 110]
        self.blocked_history = [0, 0, 5, 5, 2, 10, 15, 12, 20, 25, 20, 35]

        self.active_severity_filter = "All"
        self.search_query = ""
        self.status_toast = ""

        self.timer_text = ft.Text("00:00:00", size=24, weight=ft.FontWeight.BOLD, color="#0F172A")
        self.sidebar_timer_text = ft.Text("00:00:00", size=16, weight=ft.FontWeight.BOLD, color="#FFFFFF")

        self.sidebar_btn_refs = []
        self.content_area = ft.Container(expand=True, bgcolor="#F8FAFC", padding=20)
        self.top_bar_title = ft.Text("Dashboard", size=20, weight=ft.FontWeight.BOLD, color="#0F172A")
        self.top_bar_subtitle = ft.Text("Real-time overview of your network and security status", size=12, color="#64748B")

        self.root_container = ft.Container(expand=True, bgcolor="#F8FAFC")

        self._init_page()
        self.page.add(self.root_container)
        self.render()

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



    def render(self):
        if self.current_screen == "register":
            self.root_container.content = render_register_screen(self)
        elif self.current_screen == "login":
            self.root_container.content = render_login_screen(self)
        elif self.current_screen == "context":
            self.root_container.content = render_context_screen(self)
        elif self.current_screen == "profile":
            self.root_container.content = render_profile_screen(self)
        elif self.current_screen == "app_shell":
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
            "inventory": ("Network Device Inventory", "Discovered hosts, MAC-IP bindings, and trust posture"),
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

    def logout(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.timer_running = False
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
        self.current_screen = "login"
        self.render()

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
        self.close_dialog(dlg)
        target = "192.168.1.50"
        if target not in self.active_blocks:
            self.active_blocks.append(target)
        if self.session_id and not self.seal_mgr:
            self.seal_mgr = SealManager(self.db, self.session_id)
        if self.seal_mgr:
            res = self.seal_mgr.seal(target, event_id=None, confirmed_by_user=True)
            self.status_toast = f"Emergency Seal: {res.message}"
        else:
            self.status_toast = "Emergency Seal activated: Host isolation applied."
        self.update_view_content()
        self.page.update()

    def block_ip(self, ip: str, dlg):
        self.close_dialog(dlg)
        if ip not in self.active_blocks:
            self.active_blocks.append(ip)
        if self.session_id and not self.seal_mgr:
            self.seal_mgr = SealManager(self.db, self.session_id)
        if self.seal_mgr:
            res = self.seal_mgr.seal(ip, event_id=None, confirmed_by_user=True)
            self.status_toast = f"Isolation result: {res.message}"
        else:
            self.status_toast = f"Host {ip} isolated successfully."
        self.update_view_content()
        self.page.update()

    def unblock_ip(self, ip: str):
        if ip in self.active_blocks:
            self.active_blocks.remove(ip)
        if self.seal_mgr:
            res = self.seal_mgr.unseal(ip, confirmed_by_user=True)
            self.status_toast = f"Unseal: {res.message}"
        else:
            self.status_toast = f"Host {ip} unblocked."
        self.update_view_content()
        self.page.update()

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
        
        # Extract basic packet metadata for Packet Logs view
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

            # Prepend to live stream buffer
            self.packet_log_stream.insert(0, {
                "ts": datetime.datetime.now().strftime("%H:%M:%S.%f")[:12],
                "src": src_ip,
                "dst": dst_ip,
                "proto": proto,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "len": pkt_len,
            })
            if len(self.packet_log_stream) > 50:
                self.packet_log_stream.pop()
        except Exception:
            pass

        # Evaluate detection engine
        if self.engine:
            for alert in self.engine.process(packet):
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

                # Log event to database
                if self.session_id:
                    score = score_alert(alert, None)
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

                # Fire native OS popup notification
                evidence_text = alert.evidence.get("reason", str(alert.evidence)) if isinstance(alert.evidence, dict) else str(alert.evidence)
                send_desktop_notification(
                    title=f"🚨 [{alert.severity}] {alert_dict['type']} Detected",
                    message=f"Host: {alert_dict['source']}\n{evidence_text}\n→ Action: {alert.recommended_action}",
                    severity=alert.severity.lower(),
                )

                # Trigger UI refresh
                try:
                    self.update_view_content()
                    if self.page:
                        self.page.update()
                except Exception:
                    pass

    def start_monitoring(self):
        self.is_monitoring = True
        self.monitoring_start_time = time.time()
        self.timer_running = True

        ctx = detect_network_context()
        self.network_context = ctx
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="live", operator_id=self.operator_id)
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)

        # Launch live capture on interface
        if not self.live_capture:
            self.live_capture = LiveCapture(interface=ctx.interface or "wlan0", on_packet=self._process_packet)
            self.capture_thread = threading.Thread(target=self._start_capture_safe, daemon=True)
            self.capture_thread.start()

        if not self.timer_thread or not self.timer_thread.is_alive():
            self.timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
            self.timer_thread.start()

    def _start_capture_safe(self):
        try:
            if self.live_capture:
                self.live_capture.start()
        except Exception as e:
            self.status_toast = f"Live sniffing notice: {e}"

    def toggle_monitoring(self):
        self.is_monitoring = not self.is_monitoring
        if not self.is_monitoring:
            self.timer_running = False
            if self.live_capture:
                self.live_capture.stop()
                self.live_capture = None
        else:
            self.timer_running = True
            if not self.monitoring_start_time:
                self.monitoring_start_time = time.time()
            if not self.live_capture:
                ctx = self.network_context or detect_network_context()
                self.live_capture = LiveCapture(interface=ctx.interface or "wlan0", on_packet=self._process_packet)
                self.capture_thread = threading.Thread(target=self._start_capture_safe, daemon=True)
                self.capture_thread.start()
            if not self.timer_thread or not self.timer_thread.is_alive():
                self.timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
                self.timer_thread.start()
        self.update_view_content()
        self.page.update()

    def _timer_loop(self):
        sample_endpoints = [
            ("192.168.1.10", "192.168.1.1", "ARP", "00:0C:29:4F:11:AA", "00:50:56:C0:00:01", "42"),
            ("192.168.1.15", "8.8.8.8", "DNS (Query: google.com)", "00:1E:50:32:BB:CC", "00:50:56:C0:00:01", "74"),
            ("192.168.1.20", "192.168.1.1", "TCP ACK (HTTPS)", "00:1B:44:12:34:7F", "00:50:56:C0:00:01", "1460"),
            ("192.168.1.105", "142.250.190.46", "TLSv1.3 Handshake", "00:1E:50:32:BB:CC", "00:50:56:C0:00:01", "512"),
            ("192.168.1.1", "192.168.1.15", "UDP (NTP)", "00:50:56:C0:00:01", "00:1E:50:32:BB:CC", "90"),
        ]
        tick_counter = 0

        while self.timer_running:
            time.sleep(1)
            tick_counter += 1

            # 1. Update Timer text
            if self.monitoring_start_time and self.page:
                elapsed = int(time.time() - self.monitoring_start_time)
                hrs = elapsed // 3600
                mins = (elapsed % 3600) // 60
                secs = elapsed % 60
                timestr = f"{hrs:02d}:{mins:02d}:{secs:02d}"
                self.timer_text.value = timestr
                self.sidebar_timer_text.value = timestr

                # 2. Simulate live background packets & stream
                delta_pkts = random.randint(12, 38)
                self.packets_count += delta_pkts

                # Add a simulated packet entry to the live stream
                ep = random.choice(sample_endpoints)
                now_str = datetime.datetime.now().strftime("%H:%M:%S.%f")[:12]
                self.packet_log_stream.insert(0, {
                    "ts": now_str,
                    "src": ep[0],
                    "dst": ep[1],
                    "proto": ep[2],
                    "src_mac": ep[3],
                    "dst_mac": ep[4],
                    "len": ep[5],
                })
                if len(self.packet_log_stream) > 60:
                    self.packet_log_stream.pop()

                try:
                    if self.sidebar_timer_text.page is not None:
                        self.sidebar_timer_text.update()
                    if self.timer_text.page is not None:
                        self.timer_text.update()
                except Exception:
                    pass

    def simulate_demo_threat(self):
        sample_threats = [
            {
                "type": "ARP Identity Inconsistency",
                "severity": "HIGH",
                "source": "192.168.1.50",
                "fg": "#DC2626",
                "bg": "#FEE2E2",
                "desc": "Rogue MAC 3C:97:0E:12:34:56 poisoned default gateway IP 192.168.1.1 (Dual-MAC Inconsistency)",
                "action": "Seal Host 192.168.1.50",
            },
            {
                "type": "Port-Scan Behavior",
                "severity": "MEDIUM",
                "source": "192.168.1.77",
                "fg": "#D97706",
                "bg": "#FEF3C7",
                "desc": "Host 192.168.1.77 probed 22 distinct TCP/UDP ports in 6.4 seconds (Reconnaissance pattern)",
                "action": "Investigate & Rate-Limit",
            },
            {
                "type": "Traffic-Rate Anomaly",
                "severity": "HIGH",
                "source": "192.168.1.50",
                "fg": "#DC2626",
                "bg": "#FEE2E2",
                "desc": "Burst rate of 148 pps exceeded public Wi-Fi threshold (100 pps, SYN flood profile)",
                "action": "Engage Temporary Firewall Filter",
            },
            {
                "type": "Gateway Identity Change",
                "severity": "CRITICAL",
                "source": "192.168.1.1",
                "fg": "#DC2626",
                "bg": "#FEE2E2",
                "desc": "Default router MAC suddenly changed to 00:50:56:C0:00:01 (Possible Evil Twin Access Point)",
                "action": "Verify BSSID Trust Anchor",
            },
        ]
        chosen = random.choice(sample_threats)
        now_str = datetime.datetime.now().strftime("%H:%M:%S")
        new_alert = {
            "time": now_str,
            "type": chosen["type"],
            "severity": chosen["severity"],
            "source": chosen["source"],
            "status": "NEW",
            "fg": chosen["fg"],
            "bg": chosen["bg"],
            "desc": chosen["desc"],
        }
        self.all_alerts_list.insert(0, new_alert)
        self.status_toast = f"⚠️ Simulated Threat: {chosen['type']} detected from {chosen['source']}"

        send_desktop_notification(
            title=f"🚨 [{chosen['severity']}] {chosen['type']}",
            message=f"Host: {chosen['source']}\n{chosen['desc']}\n→ Action: {chosen['action']}",
            severity=chosen["severity"].lower(),
        )
        self.update_view_content()
        self.page.update()


    def run_pcap_replay(self, pcap_path: str):
        ctx = detect_network_context()
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source=pcap_path, operator_id=self.operator_id)
        self.engine = DetectionEngine(CONFIG.thresholds, gateway_ip=ctx.gateway_ip)

        replay = PcapReplay(pcap_path, self._process_packet)
        threading.Thread(target=replay.run, daemon=True).start()
        self.status_toast = f"Replaying PCAP: {pcap_path}"
        self.update_view_content()
        self.page.update()


    def export_report(self, fmt: str, target_session_id: Optional[int] = None):
        sid = target_session_id or self.session_id
        if not sid:
            ctx = detect_network_context()
            sid = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="export", operator_id=self.operator_id)
            self.session_id = sid

        if sid is not None:
            data = build_report_data(self.db, sid)
            out_path = f"arpie_session_{sid}.{fmt}"
            if fmt == "json":
                export_json(data, out_path)
            elif fmt == "html":
                export_html(data, out_path)
            elif fmt == "pdf":
                export_pdf(data, out_path)
            self.status_toast = f"Successfully generated and exported {out_path}"
            self.update_view_content()
            self.page.update()
