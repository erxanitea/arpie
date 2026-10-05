import os
import platform
import re
import subprocess
from contextlib import suppress
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
    with suppress(Exception):
        import netifaces  # type: ignore[import-not-found,import-untyped]
        gws = netifaces.gateways()
        default = gws.get("default", {})
        for fam in (netifaces.AF_INET, netifaces.AF_INET6):
            if fam in default:
                return default[fam][0]
    # Fallback: parse `ip route` (Linux) or `route print` (Windows)
    with suppress(Exception):
        system = platform.system()
        if system == "Linux":
            out = subprocess.check_output(["ip", "route"], text=True, timeout=3)
            if m := re.search(r"default via (\S+)", out):
                return m[1]
        elif system == "Windows":
            out = subprocess.check_output(["ipconfig"], text=True, timeout=5)
            if m := re.search(r"Default Gateway[ .]*: (\S+)", out):
                return m[1]
        elif system == "Darwin":
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True, timeout=3)
            if m := re.search(r"gateway: (\S+)", out):
                return m[1]
    return None


def _get_gateway_mac(gw_ip: Optional[str]) -> Optional[str]:
    if not gw_ip:
        return None
    with suppress(Exception):
        system = platform.system()
        if system == "Linux":
            with suppress(Exception):
                with open("/proc/net/arp", "r") as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == gw_ip and parts[3] != "00:00:00:00:00:00":
                            return parts[3].lower()
            out = subprocess.check_output(["ip", "neigh"], text=True, timeout=3, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if gw_ip in line and "lladdr" in line:
                    parts = line.split()
                    if "lladdr" in parts:
                        idx = parts.index("lladdr")
                        if idx + 1 < len(parts):
                            return parts[idx + 1].lower()
        elif system in ("Windows", "Darwin"):
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=3, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if gw_ip in line:
                    if m := re.search(r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})", line):
                        return m[1].replace("-", ":").lower()
    return None


def _get_ssid() -> Optional[str]:
    system = platform.system()
    with suppress(Exception):
        if system == "Windows":
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"], text=True, timeout=5
            )
            m = re.search(r"^\s*SSID\s*: (.+)$", out, re.MULTILINE)
            return m[1].strip() if m else None
        elif system == "Darwin":
            out = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/"
                 "Resources/airport", "-I"],
                text=True, timeout=5,
            )
            m = re.search(r"\bSSID: (.+)", out)
            return m[1].strip() if m else None
        elif system == "Linux":
            # Check nmcli (NetworkManager - standard on modern Linux desktops)
            with suppress(Exception):
                out = subprocess.check_output(
                    ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                    text=True, timeout=3, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    if line.startswith("yes:"):
                        if ssid := line.split(":", 1)[1].strip():
                            return ssid
            # Fallback to iwgetid
            with suppress(Exception):
                out = subprocess.check_output(["iwgetid", "-r"], text=True, timeout=3, stderr=subprocess.DEVNULL)
                if ssid := out.strip():
                    return ssid
            # Fallback to iw
            with suppress(Exception):
                out = subprocess.check_output(["iw", "dev"], text=True, timeout=3, stderr=subprocess.DEVNULL)
                if m := re.search(r"\bssid\s+(.+)$", out, re.MULTILINE):
                    return m[1].strip()
            return None
        return None
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
    iface = os.environ.get("ARPIE_IFACE", "").strip() or _default_interface()
    ssid = _get_ssid()
    gateway_ip = _get_gateway_ip()
    gateway_mac = _get_gateway_mac(gateway_ip)
    classification = classify_network(ssid, known_trusted_ssids)
    return NetworkContext(
        interface=iface,
        ssid=ssid,
        gateway_ip=gateway_ip,
        gateway_mac=gateway_mac,
        classification=classification,
        known_trusted_ssids=known_trusted_ssids,
    )
