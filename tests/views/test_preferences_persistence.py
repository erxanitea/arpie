from arpie.models import Database


def test_detection_preferences_round_trip(tmp_path):
    db = Database(str(tmp_path / "preferences.db"))
    thresholds = {"traffic": "250", "port": "30", "arp_window": "10", "gw_window": "20"}
    rules = {"arp": True, "port_scan": False, "traffic_rate": True, "gateway": False}

    for key, value in thresholds.items():
        db.set_config(f"detection_threshold_{key}", value)
    for key, enabled in rules.items():
        db.set_config(f"detection_rule_{key}", "1" if enabled else "0")

    assert {key: db.get_config(f"detection_threshold_{key}") for key in thresholds} == thresholds
    assert {key: db.get_config(f"detection_rule_{key}") == "1" for key in rules} == rules