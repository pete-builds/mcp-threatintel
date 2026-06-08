"""AlienVault OTX API client.

Free API key required (https://otx.alienvault.com/).
Provides community threat pulses with IOCs and MITRE ATT&CK mappings.
"""

import logging

from .base import BaseClient

logger = logging.getLogger("threatintel.otx")


class OtxClient(BaseClient):
    """AlienVault OTX API client."""

    def __init__(self, api_key: str):
        super().__init__(
            "https://otx.alienvault.com",
            headers={"X-OTX-API-KEY": api_key},
            rate_limit=0.5,
        )

    async def get_subscribed_pulses(self, modified_since: str = "", limit: int = 50) -> list[dict]:
        """Get pulses from subscribed feeds.

        Args:
            modified_since: ISO timestamp to get only pulses modified after this time.
            limit: Max pulses per page.
        """
        params = {"limit": limit}
        if modified_since:
            params["modified_since"] = modified_since

        data = await self.get("/api/v1/pulses/subscribed", params=params)
        pulses = data.get("results", [])
        logger.info("otx: fetched %d subscribed pulses", len(pulses))
        return pulses

    async def get_pulse_detail(self, pulse_id: str) -> dict:
        """Get full details for a specific pulse."""
        return await self.get(f"/api/v1/pulses/{pulse_id}")

    async def get_indicator(self, indicator_type: str, indicator: str) -> dict:
        """Look up an indicator in OTX.

        Args:
            indicator_type: One of: IPv4, IPv6, domain, hostname, url, FileHash-MD5,
                FileHash-SHA1, FileHash-SHA256, CVE, email
            indicator: The indicator value.
        """
        return await self.get(f"/api/v1/indicators/{indicator_type}/{indicator}/general")

    def shape_pulse(self, p: dict) -> dict:
        """Shape a raw OTX pulse into our schema."""
        import json
        return {
            "pulse_id": p.get("id"),
            "name": p.get("name", ""),
            "description": p.get("description", ""),
            "author": p.get("author_name", ""),
            "created": p.get("created"),
            "modified": p.get("modified"),
            "tags": json.dumps(p.get("tags", [])),
            "tlp": p.get("tlp", ""),
            "references_list": json.dumps(p.get("references", [])),
            "adversary": p.get("adversary", ""),
            "targeted_countries": json.dumps(p.get("targeted_countries", [])),
            "malware_families": json.dumps(p.get("malware_families", [])),
            "attack_ids": json.dumps([a.get("id", "") for a in p.get("attack_ids", [])]),
            "raw_json": json.dumps(p),
        }

    def shape_indicators(self, pulse_id: str, indicators: list[dict]) -> list[tuple]:
        """Extract indicators from a pulse."""
        results = []
        for ind in indicators:
            ioc = ind.get("indicator")
            ioc_type = _otx_type(ind.get("type", ""))
            if ioc and ioc_type:
                results.append((pulse_id, ioc, ioc_type))
        return results


def _otx_type(otx_type: str) -> str:
    """Map OTX indicator types to our standard types."""
    mapping = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
        "email": "email",
        "CVE": "cve",
    }
    return mapping.get(otx_type, otx_type)
