"""
Central configuration for Arpie.

All detection thresholds are configurable here (and overridable at
runtime via the Evaluator/Administrator role in the UI).
"""

import os
from dataclasses import dataclass, field


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


@dataclass
class AppConfig:
    app_name: str = "Arpie"
    db_path: str = os.environ.get("ARPIE_DB_PATH", "arpie.db")
    interface: str = os.environ.get("ARPIE_IFACE", "")   # empty = auto-detect
    thresholds: DetectionThresholds = field(default_factory=DetectionThresholds)
    seal: SealModeConfig = field(default_factory=SealModeConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)


CONFIG = AppConfig()
