"""
Rule 4 — Gateway Identity Change

Trigger: the gateway's MAC/IP association changes more than once
within a 10-minute (configurable) window — a strong signal of default
route hijacking / rogue gateway attacks.
"""

import time
from collections import deque
from typing import Optional

from scapy.layers.l2 import ARP

from . import Alert


class GatewayChangeRule:
    def __init__(self, thresholds, gateway_ip: Optional[str] = None):
        self.window = thresholds.gateway_window_seconds
        self.max_changes = thresholds.gateway_max_changes
        self.gateway_ip = gateway_ip
        self._current_mac: Optional[str] = None
        self._changes: deque = deque()   # timestamps of MAC changes
        self._already_alerted = 0.0

    def set_gateway_ip(self, gateway_ip: str):
        self.gateway_ip = gateway_ip

    def inspect(self, packet):
        if not self.gateway_ip or not packet.haslayer(ARP):
            return None
        arp = packet[ARP]
        if arp.psrc != self.gateway_ip:
            return None

        now = time.time()
        new_mac = arp.hwsrc

        if self._current_mac is None:
            self._current_mac = new_mac
            return None

        if new_mac != self._current_mac:
            self._changes.append(now)
            old_mac = self._current_mac
            self._current_mac = new_mac

        while self._changes and now - self._changes[0] > self.window:
            self._changes.popleft()

        if len(self._changes) > self.max_changes:
            if now - self._already_alerted < 30:
                return None
            self._already_alerted = now

            return Alert(
                detection_type="gateway_change",
                source_ip=self.gateway_ip,
                target=self.gateway_ip,
                severity="critical",
                confidence=0.9,
                evidence={
                    "gateway_ip": self.gateway_ip,
                    "changes_in_window": len(self._changes),
                    "window_seconds": self.window,
                    "current_mac": self._current_mac,
                },
                recommended_action="Possible rogue gateway / default-route hijack — "
                                    "verify network and enable Seal Mode immediately",
            )
        return None
