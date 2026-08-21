"""
Detection-rule tests using synthetic Scapy packets (no live interface or
real PCAP file required, so this runs anywhere — including CI).
"""

from scapy.all import Ether, ARP, IP, TCP, UDP, ICMP

from arpie.detection.arp_spoof import ArpIdentityRule
from arpie.detection.port_scan import PortScanRule
from arpie.detection.traffic_anomaly import TrafficRateRule
from arpie.detection.gateway_change import GatewayChangeRule


def make_arp(psrc, hwsrc, op=2):
    return Ether() / ARP(psrc=psrc, hwsrc=hwsrc, op=op)


def make_tcp(src, dst, dport, flags="S"):
    return Ether() / IP(src=src, dst=dst) / TCP(dport=dport, flags=flags)


def make_udp(src, dst, dport):
    return Ether() / IP(src=src, dst=dst) / UDP(dport=dport)


def make_icmp(src, dst):
    return Ether() / IP(src=src, dst=dst) / ICMP()


class TestArpIdentityRule:
    def test_single_mac_no_alert(self, fast_thresholds):
        rule = ArpIdentityRule(fast_thresholds)
        assert rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa")) is None
        assert rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa")) is None

    def test_two_macs_same_ip_alerts(self, fast_thresholds):
        rule = ArpIdentityRule(fast_thresholds)
        rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        alert = rule.inspect(make_arp("192.168.1.1", "bb:bb:bb:bb:bb:bb"))
        assert alert is not None
        assert alert.detection_type == "arp_spoof"
        assert alert.source_ip == "192.168.1.1"
        assert len(alert.evidence["macs_observed"]) == 2

    def test_ignores_non_arp_packets(self, fast_thresholds):
        rule = ArpIdentityRule(fast_thresholds)
        assert rule.inspect(make_tcp("10.0.0.1", "10.0.0.2", 80)) is None


class TestPortScanRule:
    def test_below_threshold_no_alert(self, fast_thresholds):
        rule = PortScanRule(fast_thresholds)
        for port in [22, 80]:
            assert rule.inspect(make_tcp("10.0.0.5", "10.0.0.1", port)) is None

    def test_above_threshold_alerts(self, fast_thresholds):
        rule = PortScanRule(fast_thresholds)  # threshold = 3 unique ports
        alert = None
        for port in [21, 22, 23, 25]:
            alert = rule.inspect(make_tcp("10.0.0.5", "10.0.0.1", port))
        assert alert is not None
        assert alert.detection_type == "port_scan"
        assert alert.source_ip == "10.0.0.5"
        assert alert.evidence["unique_ports_contacted"] == 4

    def test_udp_ports_also_counted(self, fast_thresholds):
        rule = PortScanRule(fast_thresholds)
        alert = None
        for port in [53, 67, 123, 161]:
            alert = rule.inspect(make_udp("10.0.0.5", "10.0.0.1", port))
        assert alert is not None


class TestTrafficRateRule:
    def test_below_threshold_no_alert(self, fast_thresholds):
        rule = TrafficRateRule(fast_thresholds)  # threshold = 5 pps
        for _ in range(3):
            result = rule.inspect(make_icmp("10.0.0.9", "10.0.0.1"))
        assert result is None

    def test_above_threshold_alerts(self, fast_thresholds):
        rule = TrafficRateRule(fast_thresholds)  # threshold = 5 pps
        # The anti-alert-storm cooldown means only the FIRST packet that
        # crosses the threshold returns an alert — later packets in the
        # same burst correctly return None, so capture the first hit.
        alert = None
        for _ in range(8):
            result = rule.inspect(make_icmp("10.0.0.9", "10.0.0.1"))
            if result is not None:
                alert = result
                break
        assert alert is not None
        assert alert.detection_type == "traffic_anomaly"
        assert alert.evidence["dominant_protocol"] == "ICMP"

    def test_syn_flood_detected(self, fast_thresholds):
        rule = TrafficRateRule(fast_thresholds)
        alert = None
        for _ in range(8):
            result = rule.inspect(make_tcp("10.0.0.9", "10.0.0.1", 80, flags="S"))
            if result is not None:
                alert = result
                break
        assert alert is not None
        assert alert.evidence["dominant_protocol"] == "SYN"

    def test_established_tcp_not_counted(self, fast_thresholds):
        rule = TrafficRateRule(fast_thresholds)
        result = None
        for _ in range(8):
            # ACK-only packets (no SYN) should not trigger the flood rule
            result = rule.inspect(make_tcp("10.0.0.9", "10.0.0.1", 80, flags="A"))
        assert result is None


class TestGatewayChangeRule:
    def test_no_alert_on_first_sighting(self, fast_thresholds):
        rule = GatewayChangeRule(fast_thresholds, gateway_ip="192.168.1.1")
        assert rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa")) is None

    def test_single_change_no_alert(self, fast_thresholds):
        rule = GatewayChangeRule(fast_thresholds, gateway_ip="192.168.1.1")  # max_changes=1
        rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        result = rule.inspect(make_arp("192.168.1.1", "bb:bb:bb:bb:bb:bb"))
        assert result is None  # exactly at threshold, not over it

    def test_multiple_changes_alerts(self, fast_thresholds):
        rule = GatewayChangeRule(fast_thresholds, gateway_ip="192.168.1.1")
        rule.inspect(make_arp("192.168.1.1", "aa:aa:aa:aa:aa:aa"))
        rule.inspect(make_arp("192.168.1.1", "bb:bb:bb:bb:bb:bb"))
        alert = rule.inspect(make_arp("192.168.1.1", "cc:cc:cc:cc:cc:cc"))
        assert alert is not None
        assert alert.detection_type == "gateway_change"
        assert alert.severity == "critical"

    def test_ignores_arp_from_non_gateway_ip(self, fast_thresholds):
        rule = GatewayChangeRule(fast_thresholds, gateway_ip="192.168.1.1")
        assert rule.inspect(make_arp("192.168.1.99", "aa:aa:aa:aa:aa:aa")) is None
