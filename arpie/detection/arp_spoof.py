"""
Rule 1 — ARP Identity Inconsistency

Trigger: one local IP is associated with more than one MAC address
within a 5-minute (configurable) window. This is the classic ARP
spoofing / MITM signature.
"""

import time
from collections import defaultdict

from scapy.layers.l2 import ARP

from . import Alert


class ArpIdentityRule:
    def __init__(self, thresholds):
        self.window = thresholds.arp_window_seconds
        self.max_macs = thresholds.arp_max_macs_per_ip
        # ip -> {mac: last_seen_ts}
        self._ip_macs: dict[str, dict[str, float]] = defaultdict(dict)
        # de-dupe so a still-inconsistent IP doesn't re-alert every packet
        self._already_alerted: dict[str, float] = {}

    def _prune(self, ip: str, now: float):
        macs = self._ip_macs[ip]
        for mac in list(macs.keys()):
            if now - macs[mac] > self.window:
                del macs[mac]

    def inspect(self, packet):
        if not packet.haslayer(ARP):
            return None
        arp = packet[ARP]
        # op 2 = is-at (reply); most spoofing relies on unsolicited replies,
        # but we track both requests and replies to catch gratuitous ARP too.
        ip = arp.psrc
        mac = arp.hwsrc
        if not ip or not mac or ip == "0.0.0.0":
            return None

        now = time.time()
        self._prune(ip, now)
        self._ip_macs[ip][mac] = now

        macs_seen = self._ip_macs[ip]
        if len(macs_seen) > self.max_macs:
            last_alert = self._already_alerted.get(ip, 0)
            if now - last_alert < 30:   # avoid alert-storming on the same IP
                return None
            self._already_alerted[ip] = now

            mac_list = sorted(macs_seen.keys())
            return Alert(
                detection_type="arp_spoof",
                source_ip=ip,
                target=ip,
                severity="high",
                confidence=0.87,
                evidence={
                    "ip": ip,
                    "macs_observed": mac_list,
                    "window_seconds": self.window,
                    "reason": f"{len(mac_list)} distinct MAC addresses claimed IP {ip} "
                              f"within {self.window}s",
                },
                recommended_action="Enable Seal Mode or manually verify the device at this IP",
            )
        return None
