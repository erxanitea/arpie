"""
Detects the current network context: SSID, interface, gateway, and a
trusted / public-untrusted / unknown classification.

Cross-platform best-effort using psutil + platform-specific fallbacks.
Wi-Fi SSID / security lookups differ per OS, so this degrades gracefully
to "unknown" fields rather than raising when a platform call is
unavailable (e.g. running inside a VM/CI without a wireless adapter).
"""

import platform
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

import psutil  # type: ignore[import-untyped]


@dataclass
class NetworkContext:
    interface: str = ""
    ssid: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    security: Optional[str] = None
    classification: str = "unknown"   # trusted / public-untrusted / unknown
    known_trusted_ssids: list = field(default_factory=list)


def _default_interface() -> str:
    """Pick the first 'up' non-loopback interface with an IP address."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, st in stats.items():
        if not st.isup or name.lower().startswith("lo"):
            continue
        if name in addrs and any(a.family.name in ("AF_INET", "AF_INET6") for a in addrs[name]):
            return name
    return next(iter(stats), "")


def _get_gateway_ip() -> Optional[str]:
    try:
        import netifaces  # type: ignore[import-not-found,import-untyped]
        gws = netifaces.gateways()
        default = gws.get("default", {})
        for fam in (netifaces.AF_INET, netifaces.AF_INET6):
            if fam in default:
                return default[fam][0]
    except Exception:
        pass
    # Fallback: parse `ip route` (Linux) or `route print` (Windows)
    try:
        system = platform.system()
        if system == "Linux":
            out = subprocess.check_output(["ip", "route"], text=True, timeout=3)
            m = re.search(r"default via (\S+)", out)
            if m:
                return m.group(1)
        elif system == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            m = re.search(r"Default Gateway[ .]*: (\S+)", out)
            if m:
                return m.group(1)
        elif system == "Darwin":
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True, timeout=3)
            m = re.search(r"gateway: (\S+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _get_ssid() -> Optional[str]:
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"], text=True, timeout=5
            )
            m = re.search(r"^\s*SSID\s*: (.+)$", out, re.MULTILINE)
            return m.group(1).strip() if m else None
        elif system == "Darwin":
            out = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/"
                 "Resources/airport", "-I"],
                text=True, timeout=5,
            )
            m = re.search(r"\bSSID: (.+)", out)
            return m.group(1).strip() if m else None
        elif system == "Linux":
            # Check nmcli (NetworkManager - standard on modern Linux desktops)
            try:
                out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                    text=True, timeout=3, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    if line.startswith("yes:"):
                        ssid = line.split(":", 1)[1].strip()
                        if ssid:
                            return ssid
            except Exception:
                pass
            # Fallback to iwgetid
            try:
                out = subprocess.check_output(["iwgetid", "-r"], text=True, timeout=3, stderr=subprocess.DEVNULL)
                ssid = out.strip()
                if ssid:
                    return ssid
            except Exception:
                pass
            # Fallback to iw
            try:
                out = subprocess.check_output(["iw", "dev"], text=True, timeout=3, stderr=subprocess.DEVNULL)
                m = re.search(r"\bssid\s+(.+)$", out, re.MULTILINE)
                if m:
                    return m.group(1).strip()
            except Exception:
                pass
            return None
        return None
    except Exception:
        return None



def classify_network(ssid: Optional[str], known_trusted_ssids: list) -> str:
    """
    trusted        — SSID matches a user-configured trusted list (home/office)
    public-untrusted — open/shared network with no known trust anchor (default
                       assumption for anything not explicitly trusted)
    unknown        — SSID/context could not be determined at all
    """
    if ssid is None:
        return "unknown"
    if known_trusted_ssids and ssid in known_trusted_ssids:
        return "trusted"
    return "public-untrusted"


def detect_network_context(known_trusted_ssids=None) -> NetworkContext:
    known_trusted_ssids = known_trusted_ssids or []
    iface = _default_interface()
    ssid = _get_ssid()
    gateway_ip = _get_gateway_ip()
    classification = classify_network(ssid, known_trusted_ssids)
    return NetworkContext(
        interface=iface,
        ssid=ssid,
        gateway_ip=gateway_ip,
        gateway_mac=None,   # resolved via ARP once capture starts
        classification=classification,
        known_trusted_ssids=known_trusted_ssids,
    )
