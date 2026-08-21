"""
Detection engine: fans each captured/replayed packet out to the four
deterministic detection rules and collects any resulting alerts.
"""

import time
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Alert:
    detection_type: str            # arp_spoof / port_scan / traffic_anomaly / gateway_change
    source_ip: Optional[str]
    target: Optional[str]
    severity: str                  # low / medium / high / critical
    confidence: float              # 0.0 - 1.0
    evidence: dict = field(default_factory=dict)
    recommended_action: str = ""
    ts: float = field(default_factory=time.time)


class DetectionEngine:
    def __init__(self, thresholds, gateway_ip: Optional[str] = None):
        # Local imports avoid a circular import at module load time.
        from .arp_spoof import ArpIdentityRule
        from .port_scan import PortScanRule
        from .traffic_anomaly import TrafficRateRule
        from .gateway_change import GatewayChangeRule

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
