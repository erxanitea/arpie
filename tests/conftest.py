import pytest

from arpie.config import DetectionThresholds


@pytest.fixture
def fast_thresholds():
    """Tight thresholds so tests don't need to wait on real time windows."""
    return DetectionThresholds(
        arp_window_seconds=5,
        arp_max_macs_per_ip=1,
        port_scan_window_seconds=5,
        port_scan_unique_ports=3,
        traffic_rate_window_seconds=1,
        traffic_rate_pps_threshold=5,
        gateway_window_seconds=5,
        gateway_max_changes=1,
    )
