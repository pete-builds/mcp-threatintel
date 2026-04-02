"""LeakCheck API client.

Paid API ($10/mo). 7B+ records from breach dumps, paste sites, dark web.
On-demand lookups only (not polled into cache).
Rate limit: 3 req/sec on Pro API.
"""

import logging

from .base import BaseClient

logger = logging.getLogger("threatintel.leakcheck")


class LeakCheckClient(BaseClient):
    """LeakCheck breach data API client."""

    def __init__(self, api_key: str):
        super().__init__(
            "https://leakcheck.io",
            headers={"X-API-Key": api_key},
            rate_limit=0.35,  # 3 req/sec max
        )

    async def lookup(self, query: str, query_type: str = "auto") -> dict:
        """Look up a value in the breach database.

        Args:
            query: The value to search for (email, domain, username, hash, phone).
            query_type: Type of query. Options: auto, email, domain, username,
                hash, phone. Default: auto (LeakCheck detects the type).

        Returns:
            Dict with match count and breach records.
        """
        params = {"query": query, "type": query_type}
        data = await self.get("/api/v2/query/", params=params)

        found = data.get("found", 0)
        results = data.get("result", [])
        logger.info("leakcheck: query=%r type=%s found=%d", query, query_type, found)

        return {
            "query": query,
            "type": query_type,
            "found": found,
            "results": [
                {
                    "source": r.get("source", {}).get("name", "unknown"),
                    "breach_date": r.get("source", {}).get("date"),
                    "email": r.get("email"),
                    "username": r.get("username"),
                    "password": _redact_password(r.get("password")),
                    "hash": r.get("hash"),
                    "fields": r.get("fields", []),
                }
                for r in results
            ],
        }

    async def lookup_domain(self, domain: str) -> dict:
        """Check all known breaches for a domain.

        Args:
            domain: Domain to check (e.g. "litellm.ai").

        Returns:
            Dict with affected accounts and breach sources.
        """
        return await self.lookup(domain, query_type="domain")


def _redact_password(pw: str | None) -> str | None:
    """Redact passwords to first 2 and last 2 chars for safety."""
    if not pw or len(pw) < 5:
        return "***" if pw else None
    return f"{pw[:2]}{'*' * (len(pw) - 4)}{pw[-2:]}"
