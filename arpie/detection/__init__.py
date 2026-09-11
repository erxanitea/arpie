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
    # UI/rule-key -> builder, so the Evaluator's on/off switches map to real rules.
    RULE_KEYS = ("arp", "port_scan", "traffic_rate", "gateway")

    def __init__(self, thresholds, gateway_ip: Optional[str] = None, enabled: Optional[dict] = None):
        enabled = enabled or {}
        builders = {
            "arp": lambda: ArpIdentityRule(thresholds),
            "port_scan": lambda: PortScanRule(thresholds),
            "traffic_rate": lambda: TrafficRateRule(thresholds),
            "gateway": lambda: GatewayChangeRule(thresholds, gateway_ip=gateway_ip),
        }
        self.rules = [build() for key, build in builders.items() if enabled.get(key, True)]

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
