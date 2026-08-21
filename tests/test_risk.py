from arpie.detection import Alert
from arpie.risk import score_alert, session_risk_score, risk_band


def test_score_alert_within_bounds():
    alert = Alert(detection_type="arp_spoof", source_ip="1.2.3.4", target="1.2.3.4",
                  severity="high", confidence=0.87, evidence={})
    score = score_alert(alert)
    assert 0 <= score <= 100


def test_critical_severity_scores_higher_than_low():
    low = Alert(detection_type="port_scan", source_ip="1.1.1.1", target="x",
               severity="low", confidence=0.5, evidence={})
    critical = Alert(detection_type="gateway_change", source_ip="1.1.1.1", target="x",
                     severity="critical", confidence=0.9, evidence={})
    assert score_alert(critical) > score_alert(low)


def test_session_score_empty_is_zero():
    assert session_risk_score([], {}) == 0


def test_multiple_distinct_types_increase_session_score():
    a1 = Alert(detection_type="port_scan", source_ip="1.1.1.1", target="x",
              severity="medium", confidence=0.8, evidence={})
    a2 = Alert(detection_type="arp_spoof", source_ip="1.1.1.1", target="x",
              severity="medium", confidence=0.8, evidence={})
    single = session_risk_score([a1], {})
    combined = session_risk_score([a1, a2], {})
    assert combined >= single


def test_risk_band_thresholds():
    assert risk_band(0) == "low"
    assert risk_band(30) == "medium"
    assert risk_band(60) == "high"
    assert risk_band(90) == "critical"
