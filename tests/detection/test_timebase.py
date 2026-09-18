"""
Detection must be driven by when traffic was *captured*, not by how fast packets
are fed into the engine.

Reading the wall clock inside a rule couples detection to feed speed: replaying a
capture that spans 30 seconds in a few milliseconds makes steady traffic look like
a flood. These tests pin that down — both that the rate is measured against the
capture timeline, and that a genuine burst is still caught.
"""

import time

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

from arpie.config import DetectionThresholds
from arpie.detection import DetectionEngine
from arpie.detection.timebase import ManualClock, SystemClock, observed_at


BASE_TS = 1_700_000_000.0


def icmp_at(ts, src="10.0.0.9", dst="10.0.0.1"):
    """An ICMP packet stamped as if captured at `ts`."""
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff") / IP(src=src, dst=dst) / ICMP()
    pkt.time = ts
    return pkt


def traffic_alerts(packets, thresholds=None, **engine_kwargs):
    engine = DetectionEngine(thresholds or DetectionThresholds(), **engine_kwargs)
    found = []
    for pkt in packets:
        found += [a for a in engine.process(pkt) if a.detection_type == "traffic_anomaly"]
    return found


class TestObservedAt:
    def test_prefers_the_packet_capture_timestamp(self):
        assert observed_at(icmp_at(BASE_TS)) == BASE_TS

    def test_falls_back_to_the_clock_without_a_timestamp(self):
        class Unstamped:
            time = None

        assert observed_at(Unstamped(), ManualClock(4242.0)) == 4242.0

    def test_falls_back_to_the_clock_on_a_junk_timestamp(self):
        class Junk:
            time = "not-a-number"

        assert observed_at(Junk(), ManualClock(7.0)) == 7.0

    def test_system_clock_returns_real_time(self):
        assert abs(SystemClock().now() - time.time()) < 5.0


class TestRateIsMeasuredAgainstCaptureTime:
    def test_steady_traffic_far_below_threshold_does_not_alert(self):
        """300 packets evenly spread over 30s is 10 pps against a 100 pps threshold.

        Every 1-second window holds exactly 10 packets, so nothing should fire —
        even though the engine consumes all 300 in under a millisecond.
        """
        packets = [icmp_at(BASE_TS + i * 0.1) for i in range(300)]
        assert traffic_alerts(packets) == []

    def test_genuine_burst_still_alerts(self):
        """Guard against over-correcting: a real flood must still be caught."""
        packets = [icmp_at(BASE_TS + i * 0.001) for i in range(400)]  # 1000 pps
        alerts = traffic_alerts(packets)
        assert alerts, "a 1000 pps burst must still raise traffic_anomaly"
        assert alerts[0].evidence["packets_per_second"] > 100

    def test_result_is_independent_of_feed_speed(self):
        """The same capture must yield the same alerts however fast it is replayed."""
        packets = [icmp_at(BASE_TS + i * 0.01) for i in range(250)]  # 100 pps, borderline

        fast = traffic_alerts(packets)

        engine = DetectionEngine(DetectionThresholds())
        slow = []
        for i, pkt in enumerate(packets):
            if i % 50 == 0:
                time.sleep(0.01)  # stall the feed; must not change the verdict
            slow += [a for a in engine.process(pkt) if a.detection_type == "traffic_anomaly"]

        assert len(fast) == len(slow)
        assert [a.evidence["packets_per_second"] for a in fast] == \
               [a.evidence["packets_per_second"] for a in slow]

    def test_wall_clock_time_reproduces_the_old_false_positive(self):
        """Documents the bug this module fixes.

        Passing the wall clock is exactly what the rules used to do internally.
        Steady 10 pps traffic then reads as a flood, because the measurement is
        against replay speed rather than the capture timeline.
        """
        packets = [icmp_at(BASE_TS + i * 0.1) for i in range(300)]  # 10 pps

        engine = DetectionEngine(DetectionThresholds())
        wall_clock_alerts = []
        for pkt in packets:
            wall_clock_alerts += [
                a for a in engine.process(pkt, now=time.time())
                if a.detection_type == "traffic_anomaly"
            ]

        assert wall_clock_alerts, "expected the old wall-clock path to false-positive"
        assert wall_clock_alerts[0].evidence["packets_per_second"] > 100
        # ...whereas the capture timeline correctly reports no flood at all.
        assert traffic_alerts(packets) == []


class TestAlertTimestamps:
    def test_alert_is_stamped_with_observation_time(self):
        """A replayed incident must report when it happened, not when it was parsed."""
        packets = [icmp_at(BASE_TS + i * 0.001) for i in range(400)]
        alerts = traffic_alerts(packets)
        assert alerts
        assert BASE_TS <= alerts[0].ts <= BASE_TS + 0.4
        assert alerts[0].ts < time.time() - 1000, "alert ts looks like processing time"


class TestPersistedIncidentTime:
    def test_replayed_incident_is_stored_under_its_capture_time(self):
        """A forensic report must say when the traffic happened, not when it was parsed."""
        import os
        import tempfile

        from arpie.models import Database

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            db = Database(db_path)
            session_id = db.start_session("ssid", "public-untrusted", "wlan0", source="replay")

            packets = [icmp_at(BASE_TS + i * 0.001) for i in range(400)]
            engine = DetectionEngine(DetectionThresholds())
            logged = 0
            for pkt in packets:
                for alert in engine.process(pkt):
                    db.log_event(
                        session_id, alert.detection_type, alert.source_ip, alert.target,
                        alert.severity, alert.confidence, 50, alert.evidence,
                        alert.recommended_action, ts=alert.ts,
                    )
                    logged += 1
            assert logged, "expected the burst fixture to raise at least one alert"

            for event in db.get_events(session_id):
                assert BASE_TS <= event["ts"] <= BASE_TS + 1.0, (
                    f"event ts {event['ts']} is processing time, not capture time"
                )
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_ts_defaults_to_now_for_callers_without_a_packet(self):
        """The seeder logs synthetic events with no captured packet behind them."""
        import os
        import tempfile
        import time as _time

        from arpie.models import Database

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            db = Database(db_path)
            session_id = db.start_session("ssid", "trusted", "wlan0", source="seed")
            db.log_event(session_id, "arp_spoof", "10.0.0.1", "10.0.0.1",
                         "high", 0.9, 70, {"reason": "seeded"})
            event = db.get_events(session_id)[0]
            assert abs(event["ts"] - _time.time()) < 10
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
