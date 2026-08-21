"""
Threat-intelligence enrichment for public IPs.

- AbuseIPDB: reputation / abuse confidence score
- IPinfo Lite: geolocation + ASN/ISP

Results are cached locally (SQLite, see db.py) for `cache_ttl_seconds`
so repeated alerts about the same IP don't re-hit external APIs, and so
the app still works offline against cached data.
"""

import ipaddress
import json
import time
from dataclasses import dataclass
from typing import Optional

import requests

from .db import Database
from .config import ThreatIntelConfig


@dataclass
class IpEnrichment:
    ip: str
    abuse_confidence_score: Optional[int] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    from_cache: bool = False


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved)
    except ValueError:
        return False


class ThreatIntelClient:
    def __init__(self, db: Database, config: ThreatIntelConfig):
        self.db = db
        self.config = config

    def enrich(self, ip: str) -> Optional[IpEnrichment]:
        if not is_public_ip(ip):
            return None

        cached = self.db.get_cached_ip(ip)
        if cached and (time.time() - cached["fetched_at"]) < self.config.cache_ttl_seconds:
            return IpEnrichment(
                ip=ip,
                abuse_confidence_score=cached["abuse_confidence_score"],
                country=cached["country"],
                asn=cached["asn"],
                isp=cached["isp"],
                from_cache=True,
            )

        abuse_score, country_abuse = self._query_abuseipdb(ip)
        asn, isp, country_geo = self._query_ipinfo(ip)
        country = country_abuse or country_geo

        self.db.cache_ip(
            ip, abuse_score, country, asn, isp,
            raw_json=json.dumps({"abuse_score": abuse_score, "asn": asn, "isp": isp}),
        )
        return IpEnrichment(ip=ip, abuse_confidence_score=abuse_score, country=country,
                             asn=asn, isp=isp, from_cache=False)

    def _query_abuseipdb(self, ip: str):
        if not self.config.abuseipdb_api_key:
            return None, None
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.config.abuseipdb_api_key, "Accept": "application/json"},
                timeout=self.config.request_timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return data.get("abuseConfidenceScore"), data.get("countryCode")
        except requests.RequestException:
            return None, None

    def _query_ipinfo(self, ip: str):
        if not self.config.ipinfo_api_key:
            return None, None, None
        try:
            resp = requests.get(
                f"https://api.ipinfo.io/lite/{ip}",
                params={"token": self.config.ipinfo_api_key},
                timeout=self.config.request_timeout_seconds,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("asn"), data.get("as_name") or data.get("org"), data.get("country")
        except requests.RequestException:
            return None, None, None
