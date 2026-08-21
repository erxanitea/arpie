"""
Rule 3 — Traffic-Rate Anomaly

Trigger: SYN/UDP/ICMP packets from one source exceeding 100 packets/sec
(configurable default baseline) — catches SYN floods, UDP floods, and
ICMP floods.
"""

import time
from collections import defaultdict, deque

from scapy.all import IP, TCP, UDP, ICMP

from . import Alert


class TrafficRateRule:
    def __init__(self, thresholds):
        self.window = thresholds.traffic_rate_window_seconds
        self.pps_threshold = thresholds.traffic_rate_pps_threshold
        # src_ip -> deque[timestamps] of relevant packets
        self._timestamps: dict[str, deque] = defaultdict(deque)
        self._already_alerted: dict[str, float] = {}

    def _is_relevant(self, packet) -> bool:
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN flag
            return True
        if packet.haslayer(UDP):
            return True
        if packet.haslayer(ICMP):
            return True
        return False

    def inspect(self, packet):
        if not packet.haslayer(IP) or not self._is_relevant(packet):
            return None

        src_ip = packet[IP].src
        now = time.time()
        dq = self._timestamps[src_ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()

        pps = len(dq) / self.window
        if pps > self.pps_threshold:
            last_alert = self._already_alerted.get(src_ip, 0)
            if now - last_alert < 5:
                return None
            self._already_alerted[src_ip] = now

            proto = "SYN" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else "ICMP")
            return Alert(
                detection_type="traffic_anomaly",
                source_ip=src_ip,
                target=packet[IP].dst,
                severity="high" if pps > self.pps_threshold * 3 else "medium",
                confidence=0.75,
                evidence={
                    "source_ip": src_ip,
                    "packets_per_second": round(pps, 1),
                    "threshold": self.pps_threshold,
                    "dominant_protocol": proto,
                },
                recommended_action="Possible flood/DoS behavior; consider Seal Mode to "
                                    "block the source",
            )
        return None
