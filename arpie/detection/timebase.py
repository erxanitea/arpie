"""
Time source for the detection layer.

Every windowed rule needs to know *when* a packet was observed. Reading the wall
clock inside a rule silently couples detection to how fast packets are fed in,
which makes PCAP replay measure disk speed rather than network behaviour: a
capture spanning 42 seconds replayed in milliseconds looks like a flood.

So time is an input, not an ambient read. The observation time of a packet is the
capture timestamp Scapy records on it (`packet.time`), which is correct for both
live sniffing and replay. A ``Clock`` covers the case where a packet carries no
usable timestamp, and lets tests drive windows deterministically.
"""

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Port: a source of the current time, in epoch seconds."""

    def now(self) -> float: ...


class SystemClock:
    """Real time. The default outside tests."""

    def now(self) -> float:
        return time.time()


class ManualClock:
    """Test double: time only moves when the test says so."""

    def __init__(self, start: float = 0.0):
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float) -> float:
        self._t += float(seconds)
        return self._t


_DEFAULT_CLOCK = SystemClock()


def observed_at(packet, clock: Clock | None = None) -> float:
    """When this packet was captured, in epoch seconds.

    Prefers the capture timestamp Scapy attaches to the packet, so replaying a
    PCAP reproduces the timing of the original capture. Falls back to the clock
    only when a packet carries no usable timestamp (hand-built packets, or a
    source that does not stamp them).
    """
    ts = getattr(packet, "time", None)
    if ts is not None:
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            ts = None
        else:
            if ts > 0:
                return ts
    return (clock or _DEFAULT_CLOCK).now()


__all__ = ["Clock", "SystemClock", "ManualClock", "observed_at"]
