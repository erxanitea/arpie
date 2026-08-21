"""
Detection engine: fans each captured/replayed packet out to the four
deterministic detection rules and collects any resulting alerts.
"""

import time
from typing import List, Optional

from .alert import Alert
from .arp_spoof import ArpIdentityRule
from .port_scan import PortScanRule
from .traffic_anomaly import TrafficRateRule
from .gateway_change import GatewayChangeRule


class DetectionEngine:
    def __init__(self, thresholds, gateway_ip: Optional[str] = None):
        self.rules = [
            ArpIdentityRule(thresholds),
            PortScanRule(thresholds),
            TrafficRateRule(thresholds),
            GatewayChangeRule(thresholds, gateway_ip=gateway_ip),
        ]

    def process(self, packet) -> List[Alert]:
        alerts = []
        for rule in self.rules:
            result = rule.inspect(packet)
            if result:
                if isinstance(result, list):
                    alerts.extend(result)
                else:
                    alerts.append(result)
        return alerts


__all__ = [
    "Alert",
    "DetectionEngine",
    "ArpIdentityRule",
    "PortScanRule",
    "TrafficRateRule",
    "GatewayChangeRule",
]
