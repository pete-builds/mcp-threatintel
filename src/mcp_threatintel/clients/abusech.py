"""Abuse.ch API clients: URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker.

Free API key required since June 2025. Register at https://auth.abuse.ch/
and generate an Auth-Key in your profile. Feodo Tracker JSON feed is still
unauthenticated.
"""

import logging

from .base import BaseClient

logger = logging.getLogger("threatintel.abusech")


def _abusech_headers(api_key: str) -> dict:
    """Build abuse.ch auth headers."""
    return {"Auth-Key": api_key} if api_key else {}


class URLhausClient(BaseClient):
    """URLhaus: malicious URL database."""

    def __init__(self, api_key: str = ""):
        super().__init__(
            "https://urlhaus-api.abuse.ch",
            headers=_abusech_headers(api_key),
            rate_limit=1.0,
        )

    async def get_recent(self, limit: int = 1000) -> list[dict]:
        """Get recent malicious URLs."""
        data = await self.get(f"/v1/urls/recent/limit/{limit}/")
        urls = data.get("urls", [])
        logger.info("urlhaus: fetched %d recent URLs", len(urls))
        return [
            {
                "indicator": u.get("url"),
                "type": "url",
                "source": "urlhaus",
                "first_seen": u.get("date_added"),
                "last_seen": u.get("date_added"),
                "tags": ",".join(u.get("tags", []) or []),
                "confidence": None,
                "malware_family": ",".join(u.get("tags", []) or []),
                "threat_type": u.get("threat", ""),
                "raw_json": str(u),
            }
            for u in urls
            if u.get("url")
        ]


class MalwareBazaarClient(BaseClient):
    """MalwareBazaar: malware sample database."""

    def __init__(self, api_key: str = ""):
        super().__init__(
            "https://mb-api.abuse.ch",
            headers=_abusech_headers(api_key),
            rate_limit=1.0,
        )

    async def get_recent(self, limit: int = 100) -> list[dict]:
        """Get recent malware samples."""
        data = await self.post("/api/v1/", data={"query": "get_recent", "selector": str(limit)})
        samples = data.get("data", [])
        if not isinstance(samples, list):
            samples = []
        logger.info("malwarebazaar: fetched %d recent samples", len(samples))
        results = []
        for s in samples:
            for hash_type in ["sha256_hash", "md5_hash", "sha1_hash"]:
                h = s.get(hash_type)
                if h:
                    results.append({
                        "indicator": h,
                        "type": f"hash_{hash_type.replace('_hash', '')}",
                        "source": "malwarebazaar",
                        "first_seen": s.get("first_seen"),
                        "last_seen": s.get("last_seen"),
                        "tags": ",".join(s.get("tags", []) or []),
                        "confidence": None,
                        "malware_family": s.get("signature", ""),
                        "threat_type": s.get("file_type", ""),
                        "raw_json": str(s),
                    })
        return results


class ThreatFoxClient(BaseClient):
    """ThreatFox: IOC database (IPs, domains, hashes)."""

    def __init__(self, api_key: str = ""):
        super().__init__(
            "https://threatfox-api.abuse.ch",
            headers=_abusech_headers(api_key),
            rate_limit=1.0,
        )

    async def get_recent(self, days: int = 1) -> list[dict]:
        """Get recent IOCs."""
        data = await self.post("/api/v1/", json_data={"query": "get_iocs", "days": days})
        iocs = data.get("data", [])
        if not isinstance(iocs, list):
            iocs = []
        logger.info("threatfox: fetched %d IOCs (last %d days)", len(iocs), days)
        return [
            {
                "indicator": i.get("ioc"),
                "type": _threatfox_type(i.get("ioc_type", "")),
                "source": "threatfox",
                "first_seen": i.get("first_seen_utc"),
                "last_seen": i.get("last_seen_utc") or i.get("first_seen_utc"),
                "tags": ",".join(i.get("tags", []) or []),
                "confidence": i.get("confidence_level"),
                "malware_family": i.get("malware", ""),
                "threat_type": i.get("threat_type", ""),
                "raw_json": str(i),
            }
            for i in iocs
            if i.get("ioc")
        ]


class FeodoClient(BaseClient):
    """Feodo Tracker: botnet C2 server blocklist."""

    def __init__(self):
        super().__init__("https://feodotracker.abuse.ch", rate_limit=1.0)

    async def get_blocklist(self) -> list[dict]:
        """Get the recommended C2 IP blocklist."""
        data = await self.get("/downloads/ipblocklist_recommended.json")
        ips = data if isinstance(data, list) else []
        logger.info("feodo: fetched %d C2 IPs", len(ips))
        return [
            {
                "indicator": i.get("ip_address"),
                "type": "ip",
                "source": "feodo",
                "first_seen": i.get("first_seen"),
                "last_seen": i.get("last_online"),
                "tags": i.get("malware", ""),
                "confidence": None,
                "malware_family": i.get("malware", ""),
                "threat_type": "botnet_cc",
                "raw_json": str(i),
            }
            for i in ips
            if i.get("ip_address")
        ]


def _threatfox_type(ioc_type: str) -> str:
    """Map ThreatFox IOC types to our standard types."""
    mapping = {
        "ip:port": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash_md5",
        "sha256_hash": "hash_sha256",
    }
    return mapping.get(ioc_type, ioc_type)
