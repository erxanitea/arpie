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
    assert engine.rules[0].window == 600
    assert engine.rules[1].pps_threshold == 250