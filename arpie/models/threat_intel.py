import time

from ._typing import MixinBase


class ThreatIntelCacheMixin(MixinBase):

    def get_cached_ip(self, ip):
        with self.cursor() as cur:
            cur.execute("SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,))
            row = cur.fetchone()
            return dict(row) if row else None

    def cache_ip(self, ip, abuse_confidence_score, country, asn, isp, raw_json):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO threat_intel_cache (ip, fetched_at, abuse_confidence_score, country, asn, isp, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET fetched_at=excluded.fetched_at, "
                "abuse_confidence_score=excluded.abuse_confidence_score, country=excluded.country, "
                "asn=excluded.asn, isp=excluded.isp, raw_json=excluded.raw_json",
                (ip, time.time(), abuse_confidence_score, country, asn, isp, raw_json),
            )
