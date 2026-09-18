import asyncio
import datetime
import threading
import time

from arpie.config import CONFIG
from arpie.detection import DetectionEngine
from arpie.infrastructure.capture import LiveCapture
from arpie.infrastructure import send_desktop_notification
from arpie.network import detect_network_context
from arpie.detection import score_alert
from arpie.views.theme import SEVERITY_BG, SEVERITY_COLORS
from arpie.views.mixins._typing import MixinBase


class MonitoringMixin(MixinBase):
    """Live packet capture: ingestion, passive device discovery, and the timer loop."""

    def set_traffic_interval(self, sec: int):
        self.traffic_interval_sec = max(1, sec)
        self._tick_counter = 0
        if self.current_view == "dashboard":
            slot = getattr(self, "dashboard_chart_slot", None)
            if slot and getattr(slot, "page", None):
                try:
                    from arpie.views.components.traffic_chart import build_spline_chart_content as _build_spline_chart_content
                    slot.content = _build_spline_chart_content(self)
                    slot.update()
                    return
                except Exception:
                    pass
            self.update_view_content()
            if self.page:
                self.page.update()

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
                        ts=alert.ts,
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
        from arpie.network import mac_vendor
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
        from arpie.network import arp_sweep, mac_vendor, local_ipv4_and_cidr
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
                                from arpie.views.components.traffic_chart import build_spline_chart_content as _build_spline_chart_content
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
