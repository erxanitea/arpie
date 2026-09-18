"""
Detection engine: fans each captured/replayed packet out to the four
deterministic detection rules and collects any resulting alerts.

The engine resolves each packet's observation time once and hands the same value
to every rule, so all four agree on "now" for a given packet and a replayed PCAP
reproduces the timing of the original capture. See :mod:`arpie.detection.timebase`.
"""

from typing import List, Optional

from arpie.models.alert import Alert
from arpie.detection.timebase import Clock, observed_at
from arpie.detection.rules.arp_spoof import ArpIdentityRule
from arpie.detection.rules.port_scan import PortScanRule
from arpie.detection.rules.traffic_anomaly import TrafficRateRule
from arpie.detection.rules.gateway_change import GatewayChangeRule


class DetectionEngine:
    RULE_KEYS = ("arp", "port_scan", "traffic_rate", "gateway")

    def __init__(
        self,
        thresholds,
        gateway_ip: Optional[str] = None,
        clock: Optional[Clock] = None,
        enabled: Optional[dict] = None,
    ):
        self.clock = clock
        enabled = enabled or {}
        builders = {
            "arp": lambda: ArpIdentityRule(thresholds),
            "port_scan": lambda: PortScanRule(thresholds),
            "traffic_rate": lambda: TrafficRateRule(thresholds),
            "gateway": lambda: GatewayChangeRule(thresholds, gateway_ip=gateway_ip),
        }
        self.rules = [build() for key, build in builders.items() if enabled.get(key, True)]

    def process(self, packet, now: Optional[float] = None) -> List[Alert]:
        if now is None:
            now = observed_at(packet, self.clock)
        alerts = []
        for rule in self.rules:
            result = rule.inspect(packet, now)
            if result:
                if isinstance(result, list):
                    alerts.extend(result)
                else:
                    alerts.append(result)
        # Stamp alerts with when the traffic was observed, not when we processed it,
        # so a replayed capture reports the original incident time.
        for alert in alerts:
            alert.ts = now
        return alerts


__all__ = ["DetectionEngine"]
