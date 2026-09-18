"""
Detection layer — deterministic heuristics and heuristic risk scoring.
"""

from arpie.models.alert import Alert
from arpie.detection.engine import DetectionEngine
from arpie.detection.risk import risk_band, score_alert, session_risk_score
from arpie.detection.rules.arp_spoof import ArpIdentityRule
from arpie.detection.rules.port_scan import PortScanRule
from arpie.detection.rules.traffic_anomaly import TrafficRateRule
from arpie.detection.rules.gateway_change import GatewayChangeRule

__all__ = [
    "Alert",
    "DetectionEngine",
    "risk_band",
    "score_alert",
    "session_risk_score",
    "ArpIdentityRule",
    "PortScanRule",
    "TrafficRateRule",
    "GatewayChangeRule",
]
