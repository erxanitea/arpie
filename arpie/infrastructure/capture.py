"""
Packet source abstraction: live capture (Scapy sniff) or PCAP replay.
Both feed the same callback signature so the detection engine doesn't
care where packets came from — this is what lets pytest run detection
rules deterministically against fixture PCAPs.
"""

from typing import Callable, Optional

from scapy.all import sniff, rdpcap, Packet


PacketCallback = Callable[[Packet], None]


class LiveCapture:
    """Wraps scapy.sniff for real-time interface monitoring."""

    def __init__(self, interface: str, on_packet: PacketCallback, bpf_filter: str = ""):
        self.interface = interface
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self._stop = False

    def start(self, count: int = 0):
        """Blocking call — run in a background thread from the UI layer."""
        sniff(
            iface=self.interface or None,
            prn=self.on_packet,
            filter=self.bpf_filter or None,
            store=False,
            count=count,
            stop_filter=lambda pkt: self._stop,
        )

    def stop(self):
        self._stop = True


class PcapReplay:
    """Replays a saved PCAP file through the same detection pipeline."""

    def __init__(self, path: str, on_packet: PacketCallback):
        self.path = path
        self.on_packet = on_packet

    def run(self):
        packets = rdpcap(self.path)
        for pkt in packets:
            self.on_packet(pkt)
        return len(packets)
