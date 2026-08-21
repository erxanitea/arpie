"""
Rule 2 — Port-Scan Behavior

Trigger: more than 15 (configurable) unique destination ports contacted
by one source within a 10-second (configurable) window.
"""

import time
from collections import defaultdict

from scapy.all import IP, TCP, UDP

from . import Alert


class PortScanRule:
    def __init__(self, thresholds):
        self.window = thresholds.port_scan_window_seconds
        self.threshold = thresholds.port_scan_unique_ports
        # src_ip -> {(dst_ip, dst_port): last_seen_ts}
        self._contacts: dict[str, dict[tuple, float]] = defaultdict(dict)
        self._already_alerted: dict[str, float] = {}

    def _prune(self, src_ip: str, now: float):
        contacts = self._contacts[src_ip]
        for key in list(contacts.keys()):
            if now - contacts[key] > self.window:
                del contacts[key]

    def inspect(self, packet):
        if not packet.haslayer(IP):
            return None
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport

        now = time.time()
        self._prune(src_ip, now)
        self._contacts[src_ip][(dst_ip, dst_port)] = now

        unique_ports = {port for (_, port) in self._contacts[src_ip].keys()}
        if len(unique_ports) > self.threshold:
            last_alert = self._already_alerted.get(src_ip, 0)
            if now - last_alert < self.window:
                return None
            self._already_alerted[src_ip] = now

            return Alert(
                detection_type="port_scan",
                source_ip=src_ip,
                target=dst_ip,
                severity="medium" if len(unique_ports) < self.threshold * 3 else "high",
                confidence=0.8,
                evidence={
                    "source_ip": src_ip,
                    "unique_ports_contacted": len(unique_ports),
                    "window_seconds": self.window,
                    "sample_ports": sorted(unique_ports)[:20],
                },
                recommended_action="Flag source host; consider blocking with Seal Mode "
                                    "if scan continues",
            )
        return None
