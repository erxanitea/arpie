"""
Detection tuning — the numbers that decide when a heuristic fires.

Separate from :mod:`arpie.config.settings` because these are tuned per deployment
by whoever is calibrating false-positive rates, not by whoever installs the app.
"""

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path


def user_data_dir() -> str:
    """Per-OS writable data directory for Arpie's database and reports, so a
    packaged/double-clicked binary never writes into an arbitrary CWD.

    - Windows: %APPDATA%\\Arpie
    - macOS:   ~/Library/Application Support/Arpie
    - Linux:   $XDG_DATA_HOME/arpie or ~/.local/share/arpie
    """
    override = os.environ.get("ARPIE_DATA_DIR")
    if override:
        base = Path(override)
    else:
        system = platform.system()
        if system == "Windows":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "Arpie"
        elif system == "Darwin":
            base = Path.home() / "Library" / "Application Support" / "Arpie"
        else:
            xdg = os.environ.get("XDG_DATA_HOME")
            base = (Path(xdg) if xdg else Path.home() / ".local" / "share") / "arpie"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        base = Path.cwd()
    return str(base)


def _default_db_path() -> str:
    return os.environ.get("ARPIE_DB_PATH") or os.path.join(user_data_dir(), "arpie.db")


def reports_dir() -> str:
    d = os.path.join(user_data_dir(), "reports")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.getcwd()
    return d


@dataclass
class DetectionThresholds:
    # ARP Identity Inconsistency
    arp_window_seconds: int = 300          # 5-minute window
    arp_max_macs_per_ip: int = 1           # >1 MAC for same IP triggers alert

    # Port-Scan Behavior
    port_scan_window_seconds: int = 10     # 10-second window
    port_scan_unique_ports: int = 15       # >15 unique dest ports triggers alert

    # Traffic-Rate Anomaly
    traffic_rate_window_seconds: int = 1   # measured per second
    traffic_rate_pps_threshold: int = 100  # >100 pkts/sec (SYN/UDP/ICMP) from one src

    # Gateway Identity Change
    gateway_window_seconds: int = 600      # 10-minute window
    gateway_max_changes: int = 1           # >1 change in window triggers alert


@dataclass
class SealModeConfig:
    auto_restore_seconds: int = 1800       # 30 minutes
    require_confirmation: bool = True


@dataclass
class ThreatIntelConfig:
    abuseipdb_api_key: str = field(default_factory=lambda: os.environ.get("ABUSEIPDB_API_KEY", ""))
    ipinfo_api_key: str = field(default_factory=lambda: os.environ.get("IPINFO_API_KEY", ""))
    cache_ttl_seconds: int = 86400         # 24h local cache for reputation/geo lookups
    request_timeout_seconds: int = 5
