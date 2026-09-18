"""
Detection layer — the deterministic heuristics that make Arpie an NIDS.

Promoted out of ``middleware`` because a packet pipeline is not a cross-cutting
request concern: these four rules are the product's core domain.
"""

from ..models.alert import Alert
from .engine import DetectionEngine
from .rules.arp_spoof import ArpIdentityRule
from .rules.port_scan import PortScanRule
from .rules.traffic_anomaly import TrafficRateRule
from .rules.gateway_change import GatewayChangeRule

__all__ = [
    "Alert",
    "DetectionEngine",
    "ArpIdentityRule",
    "PortScanRule",
    "TrafficRateRule",
    "GatewayChangeRule",
]
