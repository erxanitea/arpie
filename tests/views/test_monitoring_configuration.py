from arpie.detection import ArpIdentityRule, TrafficRateRule
from arpie.views.mixins.monitoring_mixin import MonitoringMixin


def test_monitoring_engine_uses_configured_thresholds_and_rule_switches():
    app = MonitoringMixin.__new__(MonitoringMixin)
    app.thresholds = {
        "traffic": "250",
        "port": "30",
        "arp_window": "10",
        "gw_window": "20",
    }
    app.detection_rules = {
        "arp": True,
        "port_scan": False,
        "traffic_rate": True,
        "gateway": False,
    }

    engine = app._configured_detection_engine(gateway_ip="192.168.1.1")

    assert {type(rule).__name__ for rule in engine.rules} == {"ArpIdentityRule", "TrafficRateRule"}
    arp_rule, traffic_rule = engine.rules
    assert isinstance(arp_rule, ArpIdentityRule)
    assert isinstance(traffic_rule, TrafficRateRule)
    assert arp_rule.window == 600
    assert traffic_rule.pps_threshold == 250


def test_start_capture_safe_permission_error_preserves_monitoring():
    app = MonitoringMixin.__new__(MonitoringMixin)
    app.is_monitoring = True
    app.status_toast = ""
    app.live_capture = type("MockCapture", (), {
        "start": lambda self: (_ for _ in ()).throw(PermissionError("[Errno 1] Operation not permitted"))
    })()

    app._start_capture_safe()

    assert app.is_monitoring
    assert app.live_capture is None
    assert "Live capture notice" in app.status_toast