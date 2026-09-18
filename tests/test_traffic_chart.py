import unittest
from arpie.views.dashboard import _build_spline_chart
from arpie.views.inventory import render_inventory_view


class DummyApp:
    def __init__(self):
        self.traffic_interval_sec = 1
        self.traffic_history = [10, 20, 30]
        self.suspicious_history = [0, 1, 2]
        self.blocked_history = [0, 0, 1]
        self.traffic_timestamps = ["10:00:01", "10:00:02", "10:00:03"]
        self.devices_inventory = [
            {"hostname": "Device-No-Id", "ip": "192.168.1.50", "mac": "00:11:22:33:44:55"},
            {"id": "99", "hostname": "Device-With-Id", "ip": "192.168.1.51", "mac": "00:11:22:33:44:56", "last_seen": "5m ago"},
        ]
        self.is_monitoring = True
        self.current_view = "dashboard"
        self.dashboard_chart_slot = None
        self._tick_counter = 0

    def set_traffic_interval(self, sec: int):
        self.traffic_interval_sec = max(1, sec)
        self._tick_counter = 0

    def update_view_content(self):
        pass


class TestTrafficChartAndInventory(unittest.TestCase):
    def test_spline_chart_builds(self):
        app = DummyApp()
        chart_container = _build_spline_chart(app)
        self.assertIsNotNone(chart_container)
        self.assertEqual(app.dashboard_chart_slot, chart_container)

    def test_interval_switch(self):
        app = DummyApp()
        app.set_traffic_interval(5)
        self.assertEqual(app.traffic_interval_sec, 5)
        self.assertEqual(app._tick_counter, 0)

    def test_inventory_view_handles_missing_keys(self):
        app = DummyApp()
        view = render_inventory_view(app)
        self.assertIsNotNone(view)


if __name__ == "__main__":
    unittest.main()
