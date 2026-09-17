import ipaddress
import platform
import subprocess
from typing import Optional

import psutil  # type: ignore[import-untyped]


def local_ipv4_and_cidr(interface: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Return (local_ipv4, subnet_cidr) for the active interface.

    Prefers the named interface, then falls back to the first non-loopback
    interface that has a routable IPv4 address.
    """
    addrs = psutil.net_if_addrs()
    ordered: list[tuple[str, list]] = []
    if interface and interface in addrs:
        ordered.append((interface, addrs[interface]))
    for name, lst in addrs.items():
        if name.lower().startswith("lo") or name == interface:
            continue
        ordered.append((name, lst))

    for _name, lst in ordered:
        for a in lst:
            if a.family.name == "AF_INET" and not a.address.startswith("127."):
                ip = a.address
                mask = getattr(a, "netmask", None) or "255.255.255.0"
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    return ip, str(net)
                except Exception:
                    return ip, None
    return None, None


def mac_vendor(mac: Optional[str]) -> str:
    """Best-effort OUI → vendor name using Scapy's bundled manufacturer DB."""
    if not mac:
        return "Unknown"
    try:
        from scapy.all import conf  # type: ignore[import-untyped]
        db = getattr(conf, "manufdb", None)
        if db is not None:
            for attr in ("_get_manuf", "_get_short_manuf", "lookup"):
                fn = getattr(db, attr, None)
                if callable(fn):
                    try:
                        val = fn(mac)
                    except Exception:
                        continue
                    if isinstance(val, tuple):
                        val = val[-1]
                    if val and str(val).lower() not in ("", mac.lower(), "unknown"):
                        return str(val)
    except Exception:
        pass
    return "Unknown"


def _arp_table() -> dict[str, str]:
    """Read the OS ARP cache as a passive, unprivileged fallback (ip -> mac)."""
    table: dict[str, str] = {}
    try:
        system = platform.system()
        if system == "Windows":
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            import re
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", out):
                table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            out = subprocess.check_output(["ip", "neigh"], text=True, timeout=5)
            import re
            for line in out.splitlines():
                m = re.match(r"(\d+\.\d+\.\d+\.\d+).*?lladdr\s+([0-9a-fA-F:]{17})", line)
                if m:
                    table[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return table


def arp_sweep(cidr: str, iface: Optional[str] = None, timeout: int = 2) -> list[dict]:
    results: dict[str, str] = {}
    try:
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
        from scapy.sendrecv import srp  # type: ignore[import-untyped]

        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
            timeout=timeout, iface=iface or None, verbose=False, retry=1,
        )
        for _sent, rcv in answered:
            results[rcv.psrc] = rcv.hwsrc.lower()
    except Exception:
        pass

    # Merge in anything the kernel ARP cache already holds.
    for ip, mac in _arp_table().items():
        results.setdefault(ip, mac)

    return [{"ip": ip, "mac": mac} for ip, mac in results.items()]
