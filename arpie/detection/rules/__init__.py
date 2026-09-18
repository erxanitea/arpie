"""One module per detection rule; each exposes ``inspect(packet) -> Alert | None``."""

from arpie.detection.rules.arp_spoof import ArpIdentityRule
from arpie.detection.rules.port_scan import PortScanRule
from arpie.detection.rules.traffic_anomaly import TrafficRateRule
from arpie.detection.rules.gateway_change import GatewayChangeRule

__all__ = [
    "ArpIdentityRule",
    "PortScanRule",
    "TrafficRateRule",
    "GatewayChangeRule",
]
