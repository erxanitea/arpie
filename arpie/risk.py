"""
Transparent, explainable heuristic risk scoring (0-100).

The score is a simple weighted sum so it stays auditable — every point
added is traceable to a specific alert or enrichment fact. This is a
deliberate design choice over a black-box ML model: the proposal calls
for "explainable alerts," and a hand-tunable heuristic is easier to
justify to a non-technical end user than a classifier's probability.
"""

from typing import List, Optional

from .detection import Alert
from .threat_intel import IpEnrichment


SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 45,
}

DETECTION_TYPE_WEIGHTS = {
    "gateway_change": 15,   # route hijacking is the most dangerous local event
    "arp_spoof": 10,
    "traffic_anomaly": 5,
    "port_scan": 5,
}


def score_alert(alert: Alert, enrichment: Optional[IpEnrichment] = None) -> int:
    score = 0
    score += SEVERITY_WEIGHTS.get(alert.severity, 0)
    score += DETECTION_TYPE_WEIGHTS.get(alert.detection_type, 0)
    score += int(alert.confidence * 20)

    if enrichment and enrichment.abuse_confidence_score is not None:
        # AbuseIPDB score is already 0-100; fold in a fraction of it
        score += int(enrichment.abuse_confidence_score * 0.2)

    return max(0, min(100, score))


def session_risk_score(alerts: List[Alert], enrichments: dict) -> int:
    """
    Aggregate score for the whole session: highest single-alert score,
    nudged upward if multiple distinct detection types have fired
    (multiple independent signals are more concerning than one repeated
    alert type).
    """
    if not alerts:
        return 0

    per_alert_scores = [
        score_alert(a, enrichments.get(a.source_ip)) for a in alerts
    ]
    base = max(per_alert_scores)

    distinct_types = {a.detection_type for a in alerts}
    bonus = min(20, (len(distinct_types) - 1) * 8)

    return max(0, min(100, base + bonus))


def risk_band(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
