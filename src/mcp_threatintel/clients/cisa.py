"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

Free, no API key required. Full catalog is ~1100 entries.
"""

import logging

from .base import BaseClient

logger = logging.getLogger("threatintel.cisa")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaClient(BaseClient):
    """CISA KEV catalog client."""

    def __init__(self):
        super().__init__("https://www.cisa.gov", rate_limit=2.0)

    async def get_kev_catalog(self) -> list[dict]:
        """Fetch the full KEV catalog."""
        data = await self.get("/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        vulns = data.get("vulnerabilities", [])
        logger.info("cisa: fetched %d KEV vulnerabilities", len(vulns))
        return [
            {
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "vulnerability_name": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "known_ransomware": v.get("knownRansomwareCampaignUse"),
                "notes": v.get("notes"),
                "raw_json": str(v),
            }
            for v in vulns
            if v.get("cveID")
        ]
