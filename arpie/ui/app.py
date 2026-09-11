import datetime
import threading
import time
from collections import deque
from typing import Optional

import flet as ft

from ..capture import LiveCapture, PcapReplay
from ..config import CONFIG, DetectionThresholds
from ..db import Database
from ..detection import Alert, DetectionEngine
from ..discovery import arp_sweep, local_ipv4_and_cidr, mac_vendor
from ..network_context import detect_network_context
from ..notification import send_desktop_notification
from ..report import build_report_data, export_html, export_json, export_pdf
from ..risk import risk_band, score_alert, session_risk_score
from ..seal import SealManager, reconcile_orphaned_seals
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
            "gw_window": "10",
        }
        self._load_persisted_config()

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

        # --- Live, observation-backed state (no fabricated data) ---
        # All shared structures below are mutated from the capture thread and
        # read from the UI thread, so every access goes through _data_lock.
        self._data_lock = threading.RLock()
        self.alerts: list[Alert] = []
        self.enrichments: dict[str, IpEnrichment] = {}
        self.active_blocks: list[str] = []
        self.packets_count = 0

        self.all_alerts_list: list[dict] = []
        self.top_talkers_data: list[dict] = []
        self.devices_inventory: list[dict] = []
        self.packet_log_stream: list[dict] = []

        # Per-source packet tallies -> Top Talkers; observed MAC/IP -> inventory.
        self._talker_counts: dict[str, int] = {}
        self._device_map: dict[str, dict] = {}

        # Rolling 12-sample-per-second timelines for the dashboard chart,
        # rolled once per second from live counters in the timer loop.
        self.traffic_history = [0] * 12
        self.suspicious_history = [0] * 12
        self.blocked_history = [0] * 12
        self._sec_total = 0
        self._sec_suspicious = 0
        self._sec_blocked = 0

        self.local_ip: Optional[str] = None
        self.subnet_cidr: Optional[str] = None
        self.scan_status = ""
        self.status_toast = ""

        # Coalesced, throttled UI refresh so an attack burst can't lock the UI.
        self._ui_dirty = False
        self._last_refresh = 0.0

        # Reconcile any firewall block stranded by a previous crash/kill.
        try:
            restored = reconcile_orphaned_seals(self.db)
            if restored:
                self.status_toast = f"Startup: cleared {len(restored)} orphaned Seal rule(s): {', '.join(restored)}"
        except Exception:
            pass

        self.active_severity_filter = "All"
        self.search_query = ""

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

    # ---- configuration ----
    def _load_persisted_config(self):
        """Hydrate detection thresholds, rule toggles, and threat-intel keys
        from the operator_config table so evaluator changes survive restarts
        and actually reach CONFIG/the engine (not just the UI)."""
        try:
            for ui_key in ("traffic", "port", "arp_window", "gw_window"):
                v = self.db.get_config(f"threshold.{ui_key}", "")
                if v:
                    self.thresholds[ui_key] = v
            for rule_key in DetectionEngine.RULE_KEYS:
                v = self.db.get_config(f"rule.{rule_key}", "")
                if v:
                    self.detection_rules[rule_key] = (v == "1")
            abuse = self.db.get_config("intel.abuseipdb_key", "")
            ipinfo = self.db.get_config("intel.ipinfo_key", "")
            if abuse:
                CONFIG.threat_intel.abuseipdb_api_key = abuse
            if ipinfo:
                CONFIG.threat_intel.ipinfo_api_key = ipinfo
        except Exception:
            pass

    def _thresholds_from_ui(self) -> DetectionThresholds:
        """Translate the UI's human-facing threshold values (minutes, etc.)
        into the engine's DetectionThresholds. Falls back to defaults on any
        bad input rather than crashing the capture pipeline."""
        d = DetectionThresholds()
        try:
            d.traffic_rate_pps_threshold = int(float(self.thresholds.get("traffic", "100")))
        except (TypeError, ValueError):
            pass
        try:
            d.port_scan_unique_ports = int(float(self.thresholds.get("port", "15")))
        except (TypeError, ValueError):
            pass
        try:
            d.arp_window_seconds = int(float(self.thresholds.get("arp_window", "5")) * 60)
        except (TypeError, ValueError):
            pass
        try:
            d.gateway_window_seconds = int(float(self.thresholds.get("gw_window", "10")) * 60)
        except (TypeError, ValueError):
            pass
        return d

    def build_engine(self, gateway_ip: Optional[str] = None) -> DetectionEngine:
        """Construct a DetectionEngine from the current live thresholds and
        rule toggles. Called on session start and whenever settings change."""
        return DetectionEngine(
            self._thresholds_from_ui(),
            gateway_ip=gateway_ip,
            enabled=dict(self.detection_rules),
        )

    def save_detection_settings(self, thresholds: dict, abuse_key: str = "", ipinfo_key: str = "") -> str:
        """Persist evaluator threshold/key changes and rebuild the live engine
        so they take effect immediately for the running session."""
        for ui_key, val in thresholds.items():
            self.thresholds[ui_key] = val
            self.db.set_config(f"threshold.{ui_key}", str(val))
        for rule_key, on in self.detection_rules.items():
            self.db.set_config(f"rule.{rule_key}", "1" if on else "0")
        if abuse_key and set(abuse_key) != {"•"}:
            self.db.set_config("intel.abuseipdb_key", abuse_key)
            CONFIG.threat_intel.abuseipdb_api_key = abuse_key
        if ipinfo_key and set(ipinfo_key) != {"•"}:
            self.db.set_config("intel.ipinfo_key", ipinfo_key)
            CONFIG.threat_intel.ipinfo_api_key = ipinfo_key
        gw = self.network_context.gateway_ip if self.network_context else None
        self.engine = self.build_engine(gateway_ip=gw)
        return "Detection settings saved and applied to the live engine."

    # ---- risk ----
    @property
    def session_risk(self) -> int:
        """Aggregate session risk computed by the audited heuristic in risk.py
        from the real Alert objects — the single source of truth the CLI uses."""
        with self._data_lock:
            return session_risk_score(list(self.alerts), dict(self.enrichments))

    # ---- throttled UI refresh (safe under a packet flood) ----
    def _request_ui_refresh(self, force: bool = False):
        """Re-render at most a few times per second. During a flood we set the
        dirty flag and let the 1 Hz timer flush it, so the UI thread never
        drowns in per-packet re-renders."""
        now = time.time()
        if not force and (now - self._last_refresh) < 0.4:
            self._ui_dirty = True
            return
        self._last_refresh = now
        self._ui_dirty = False
        try:
            self.update_view_content()
            if self.page:
                self.page.update()
        except Exception:
            pass

    # ---- live device discovery ----
    def scan_subnet(self):
        """Active ARP sweep of the local subnet to enumerate live hosts.
        Runs off the UI thread; needs raw-socket privileges (falls back to the
        OS ARP cache when unprivileged)."""
        self.scan_status = "Scanning local subnet…"
        self._request_ui_refresh(force=True)

        def worker():
            iface = self.network_context.interface if self.network_context else None
            cidr = self.subnet_cidr
            if not cidr:
                self.local_ip, self.subnet_cidr = local_ipv4_and_cidr(iface)
                cidr = self.subnet_cidr
            found = arp_sweep(cidr, iface=iface) if cidr else []
            for host in found:
                self._observe_device(host["ip"], host["mac"])
            self._rebuild_inventory()
            n = len(self.devices_inventory)
            self.scan_status = (
                f"Discovered {n} host(s) on {cidr}." if found
                else "No hosts answered — ARP sweep needs admin/root; showing passively observed hosts."
            )
            self._request_ui_refresh(force=True)

        threading.Thread(target=worker, daemon=True).start()

    def _observe_device(self, ip: Optional[str], mac: Optional[str]):
        """Record a MAC/IP binding seen either passively (captured packets) or
        actively (ARP sweep). Multiple MACs for one IP is itself a signal, so
        we keep the set rather than overwriting."""
        if not ip or not mac or ip == "0.0.0.0":
            return
        mac = mac.lower()
        with self._data_lock:
            entry = self._device_map.get(ip)
            if entry is None:
                entry = {"macs": set(), "first_seen": time.time()}
                self._device_map[ip] = entry
            entry["macs"].add(mac)
            entry["last_seen"] = time.time()

    def _rebuild_inventory(self):
        """Materialize the observed device map into the table rows the
        Network view renders."""
        gw = self.network_context.gateway_ip if self.network_context else None
        rows = []
        with self._data_lock:
            items = sorted(self._device_map.items(), key=lambda kv: kv[0])
            for idx, (ip, entry) in enumerate(items, start=1):
                macs = sorted(entry["macs"])
                mac = macs[0]
                multi = len(macs) > 1
                if ip == gw:
                    dtype, status = "Gateway / Router", ("Untrusted / Suspect" if multi else "Active Gateway")
                elif ip == self.local_ip:
                    dtype, status = "Endpoint / Host", "Local Endpoint"
                else:
                    dtype, status = "Host", ("Untrusted / Suspect" if multi else "Known Host")
                rows.append({
                    "id": str(idx),
                    "hostname": "This Endpoint" if ip == self.local_ip else ("Gateway" if ip == gw else f"host-{ip.split('.')[-1]}"),
                    "ip": ip,
                    "mac": mac + (f"  (+{len(macs) - 1})" if multi else ""),
                    "vendor": mac_vendor(mac),
                    "type": dtype,
                    "status": status,
                    "last_seen": datetime.datetime.fromtimestamp(entry["last_seen"]).strftime("%Y-%m-%d %H:%M"),
                })
            self.devices_inventory = rows

    def _own_mac(self, interface: Optional[str]) -> Optional[str]:
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            if interface and interface in addrs:
                for a in addrs[interface]:
                    if a.family.name in ("AF_LINK", "AF_PACKET") and a.address:
                        return a.address.lower()
        except Exception:
            pass
        return None

    def _recompute_top_talkers(self):
        with self._data_lock:
            total = sum(self._talker_counts.values()) or 1
            top = sorted(self._talker_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]
            self.top_talkers_data = [
                {"ip": ip, "packets": cnt, "pct": f"{cnt / total * 100:.1f}%"}
                for ip, cnt in top
            ]

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
        # Emergency seal targets the source of the most recent alert.
        with self._data_lock:
            target = self.all_alerts_list[0]["source"] if self.all_alerts_list else None
        if not target or target == "Unknown":
            self.status_toast = "No attacker host to seal yet — Emergency Seal needs at least one alert."
            self.update_view_content()
            self.page.update()
            return
        self.block_ip(target, None)

    def block_ip(self, ip: str, dlg):
        if dlg is not None:
            self.close_dialog(dlg)
        if not self.seal_mgr:
            self.seal_mgr = SealManager(self.db, self.session_id or 0, CONFIG.seal.auto_restore_seconds)
        res = self.seal_mgr.seal(ip, event_id=None, confirmed_by_user=True)
        # Only list the host as blocked if the firewall rule actually applied,
        # so the Seal view never claims a block that isn't enforced.
        if res.success:
            with self._data_lock:
                if ip not in self.active_blocks:
                    self.active_blocks.append(ip)
            self.status_toast = f"Sealed {ip}: {res.message}"
        else:
            self.status_toast = f"Seal failed for {ip}: {res.message}"
        self.update_view_content()
        self.page.update()

    def unblock_ip(self, ip: str):
        with self._data_lock:
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
        """Single entry point for every captured/replayed packet. Extracts
        metadata for the live views, feeds the real detection engine, and
        enriches + scores any resulting alert exactly as the CLI path does."""
        # Extract packet metadata for the Packet Logs view and talker/device maps.
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
                self._observe_device(arp_layer.psrc, arp_layer.hwsrc)
            elif packet.haslayer("IP"):
                ip_layer = packet.getlayer("IP")
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                self._observe_device(src_ip, src_mac)
                if packet.haslayer("TCP"):
                    tcp = packet.getlayer("TCP")
                    proto = f"TCP ({tcp.dport})" if str(tcp.flags) == "S" else "TCP"
                elif packet.haslayer("UDP"):
                    proto = "UDP"
                elif packet.haslayer("ICMP"):
                    proto = "ICMP"
                else:
                    proto = "IP"
        except Exception:
            pass

        with self._data_lock:
            self.packets_count += 1
            self._sec_total += 1
            if src_ip and src_ip != "Unknown":
                self._talker_counts[src_ip] = self._talker_counts.get(src_ip, 0) + 1
                if src_ip in self.active_blocks:
                    self._sec_blocked += 1
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

        if not self.engine:
            return

        for alert in self.engine.process(packet):
            with self._data_lock:
                self._sec_suspicious += 1

            # Threat-intel enrichment (cached; only fires for public IPs) — the
            # same path the CLI uses, so the GUI risk score is genuine.
            enrichment = None
            try:
                if alert.source_ip:
                    enrichment = self.threat_intel.enrich(alert.source_ip)
                    if enrichment:
                        with self._data_lock:
                            self.enrichments[alert.source_ip] = enrichment
            except Exception:
                enrichment = None

            score = score_alert(alert, enrichment)
            evidence = alert.evidence if isinstance(alert.evidence, dict) else {"raw": str(alert.evidence)}
            reason = evidence.get("reason") or evidence.get("dominant_protocol") or str(evidence)

            alert_dict = {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "type": alert.detection_type.replace("_", " ").title(),
                "detection_type": alert.detection_type,
                "severity": alert.severity.upper(),
                "source": alert.source_ip or src_ip or "Unknown",
                "target": alert.target or "Local Endpoint",
                "confidence": alert.confidence,
                "risk_score": score,
                "status": "NEW",
                "fg": SEVERITY_COLORS.get(alert.severity.lower(), "#DC2626"),
                "bg": SEVERITY_BG.get(alert.severity.lower(), "#FEE2E2"),
                "desc": reason,
                "evidence": evidence,
                "abuse_score": enrichment.abuse_confidence_score if enrichment else None,
                "asn": enrichment.asn if enrichment else None,
                "country": enrichment.country if enrichment else None,
            }

            with self._data_lock:
                self.alerts.append(alert)
                self.all_alerts_list.insert(0, alert_dict)

            if self.session_id:
                try:
                    self.db.log_event(
                        self.session_id, alert.detection_type,
                        alert.source_ip or src_ip, alert.target,
                        alert.severity, alert.confidence, score,
                        evidence, alert.recommended_action,
                    )
                except Exception:
                    pass

            send_desktop_notification(
                title=f"🚨 [{alert.severity}] {alert_dict['type']} Detected",
                message=f"Host: {alert_dict['source']}\n{reason}\n→ Action: {alert.recommended_action}",
                severity=alert.severity.lower(),
            )

        self._recompute_top_talkers()
        self._request_ui_refresh()

    def start_monitoring(self):
        self.is_monitoring = True
        self.monitoring_start_time = time.time()
        self.timer_running = True

        ctx = detect_network_context()
        self.network_context = ctx
        self.local_ip, self.subnet_cidr = local_ipv4_and_cidr(ctx.interface)
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="live", operator_id=self.operator_id)
        self.engine = self.build_engine(gateway_ip=ctx.gateway_ip)
        self.seal_mgr = SealManager(self.db, self.session_id, CONFIG.seal.auto_restore_seconds)
        # Seed inventory with this endpoint and the gateway so the Network view
        # is populated before the first ARP sweep.
        if self.local_ip:
            self._observe_device(self.local_ip, self._own_mac(ctx.interface))
        self._rebuild_inventory()

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
        """1 Hz housekeeping: advance the session clock, roll the real
        packets-per-second timelines from live counters, and flush any
        coalesced UI refresh. It never fabricates traffic — the timelines
        reflect exactly what was captured in the preceding second."""
        while self.timer_running:
            time.sleep(1)

            if self.monitoring_start_time and self.page:
                elapsed = int(time.time() - self.monitoring_start_time)
                hrs = elapsed // 3600
                mins = (elapsed % 3600) // 60
                secs = elapsed % 60
                timestr = f"{hrs:02d}:{mins:02d}:{secs:02d}"
                self.timer_text.value = timestr
                self.sidebar_timer_text.value = timestr

                # Roll the last second's real counters into the 12-sample chart.
                with self._data_lock:
                    self.traffic_history = (self.traffic_history + [self._sec_total])[-12:]
                    self.suspicious_history = (self.suspicious_history + [self._sec_suspicious])[-12:]
                    self.blocked_history = (self.blocked_history + [self._sec_blocked])[-12:]
                    self._sec_total = self._sec_suspicious = self._sec_blocked = 0

                try:
                    if self.sidebar_timer_text.page is not None:
                        self.sidebar_timer_text.update()
                    if self.timer_text.page is not None:
                        self.timer_text.update()
                except Exception:
                    pass

                # Flush any UI refresh coalesced during a packet burst.
                if self._ui_dirty:
                    self._request_ui_refresh(force=True)

    def simulate_demo_threat(self):
        """Self-test: craft real Scapy attack packets and push them through the
        SAME detection pipeline as live capture. This is a genuine loopback
        test of the engine (no fabricated alerts) — useful for a presentation
        when a second attacker device isn't available. Detections it produces
        are indistinguishable from a real attack because they ARE produced by
        the real rules."""
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether

        if not self.engine:
            self.session_id = self.session_id or self.db.start_session(
                None, "unknown", "", source="self-test", operator_id=self.operator_id)
            self.engine = self.build_engine(gateway_ip="192.0.2.1")

        gw = (self.network_context.gateway_ip if self.network_context else None) or "192.0.2.1"
        victim = self.local_ip or "192.0.2.10"
        attacker = "192.0.2.66"

        def inject():
            # 1) ARP identity inconsistency: two MACs claim the gateway IP.
            self._process_packet(Ether() / ARP(op=2, psrc=gw, hwsrc="de:ad:be:ef:00:01", pdst=victim))
            self._process_packet(Ether() / ARP(op=2, psrc=gw, hwsrc="de:ad:be:ef:00:02", pdst=victim))
            # 2) Port scan: >15 unique destination ports from one source.
            for port in range(20, 45):
                self._process_packet(Ether() / IP(src=attacker, dst=victim) / TCP(dport=port, flags="S"))
            # 3) Traffic-rate anomaly: a burst above the pps threshold.
            for _ in range(160):
                self._process_packet(Ether() / IP(src=attacker, dst=victim) / TCP(dport=80, flags="S"))
            self._request_ui_refresh(force=True)

        self.status_toast = ("Self-test running: injecting real attack packets through the live "
                             "detection engine (ARP spoof → port scan → SYN flood).")
        self._request_ui_refresh(force=True)
        threading.Thread(target=inject, daemon=True).start()


    def run_pcap_replay(self, pcap_path: str):
        ctx = detect_network_context()
        self.network_context = ctx
        self.session_id = self.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source=pcap_path, operator_id=self.operator_id)
        self.engine = self.build_engine(gateway_ip=ctx.gateway_ip)

        self.local_ip, self.subnet_cidr = local_ipv4_and_cidr(ctx.interface)
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
            import os
            data = build_report_data(self.db, sid)
            out_path = os.path.join(CONFIG.reports_dir, f"arpie_session_{sid}.{fmt}")
            if fmt == "json":
                export_json(data, out_path)
            elif fmt == "html":
                export_html(data, out_path)
            elif fmt == "pdf":
                export_pdf(data, out_path)
            self.status_toast = f"Successfully generated and exported {out_path}"
            self.update_view_content()
            self.page.update()
