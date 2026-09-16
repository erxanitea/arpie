import time
from dataclasses import dataclass, field
from typing import Optional


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
