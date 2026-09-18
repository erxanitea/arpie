"""
Infrastructure — the only layer that talks to the operating system.

Packet capture (Scapy), desktop notifications, and platform shell-outs live here
so that privilege-touching code has a single audit surface.
"""

from .capture import LiveCapture, PcapReplay, PacketCallback
from .notifications import send_desktop_notification

__all__ = [
    "LiveCapture",
    "PcapReplay",
    "PacketCallback",
    "send_desktop_notification",
]
