"""One module per detection rule; each exposes ``inspect(packet) -> Alert | None``."""

from .arp_spoof import ArpIdentityRule
from .port_scan import PortScanRule
from .traffic_anomaly import TrafficRateRule
from .gateway_change import GatewayChangeRule

__all__ = [
    "ArpIdentityRule",
    "PortScanRule",
    "TrafficRateRule",
    "GatewayChangeRule",
]
