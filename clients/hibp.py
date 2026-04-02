"""Have I Been Pwned (HIBP) API v3 client.

Free tier: breach catalog, latest breach, pwned passwords.
Paid tier ($4.50/mo+): email/domain breach lookups, paste lookups.

API docs: https://haveibeenpwned.com/API/v3
"""

import hashlib
import logging

from .base import BaseClient

logger = logging.getLogger("threatintel.hibp")


class HibpClient(BaseClient):
    """Have I Been Pwned API v3 client."""

    def __init__(self, api_key: str = ""):
        headers = {"user-agent": "mcp-threatintel/1.0"}
        if api_key:
            headers["hibp-api-key"] = api_key
        super().__init__(
            "https://haveibeenpwned.com",
            headers=headers,
            rate_limit=6.0,  # Free tier: 10 RPM max
        )
        self._has_key = bool(api_key)

    # --- Free endpoints (no API key) ---

    async def get_all_breaches(self) -> list[dict]:
        """Get all breaches in the HIBP database."""
        data = await self.get("/api/v3/breaches")
        logger.info("hibp: fetched %d breaches", len(data))
        return data

    async def get_breach(self, name: str) -> dict:
        """Get details for a specific breach by name."""
        return await self.get(f"/api/v3/breach/{name}")

    async def get_latest_breach(self) -> dict:
        """Get the most recently added breach."""
        return await self.get("/api/v3/latestbreach")

    async def check_password(self, password: str) -> dict:
        """Check if a password has been exposed using k-anonymity.

        Only the first 5 chars of the SHA-1 hash are sent to the API.
        The full hash never leaves this machine.

        Args:
            password: The password to check.

        Returns:
            Dict with exposed count (0 = not found in any breach).
        """
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        # Pwned Passwords uses a different domain
        await self._rate_limit()
        for attempt in range(2):
            try:
                resp = await self._client.get(
                    f"https://api.pwnedpasswords.com/range/{prefix}"
                )
                resp.raise_for_status()
                text = resp.text
                break
            except Exception:
                if attempt == 0:
                    continue
                raise

        count = 0
        for line in text.splitlines():
            parts = line.strip().split(":")
            if len(parts) == 2 and parts[0] == suffix:
                count = int(parts[1])
                break

        logger.info("hibp: password check, exposed_count=%d", count)
        return {
            "exposed": count > 0,
            "count": count,
        }

    # --- Paid endpoints (API key required) ---

    async def check_email(self, email: str) -> dict:
        """Check breaches for an email address. Requires API key.

        Args:
            email: Email address to check.

        Returns:
            Dict with list of breaches, or error if no API key.
        """
        if not self._has_key:
            return {"error": "HIBP API key required for email lookups. Set HIBP_API_KEY in .env ($4.50/mo at haveibeenpwned.com/API/Key)."}

        try:
            data = await self.get(
                f"/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
            )
            logger.info("hibp: email=%r breaches=%d", email, len(data))
            return {"email": email, "breach_count": len(data), "breaches": data}
        except Exception as e:
            if "404" in str(e):
                return {"email": email, "breach_count": 0, "breaches": [], "status": "clean"}
            raise

    async def check_pastes(self, email: str) -> dict:
        """Check paste sites for an email address. Requires API key.

        Args:
            email: Email address to check.

        Returns:
            Dict with list of pastes containing this email.
        """
        if not self._has_key:
            return {"error": "HIBP API key required for paste lookups. Set HIBP_API_KEY in .env."}

        try:
            data = await self.get(f"/api/v3/pasteaccount/{email}")
            logger.info("hibp: email=%r pastes=%d", email, len(data))
            return {"email": email, "paste_count": len(data), "pastes": data}
        except Exception as e:
            if "404" in str(e):
                return {"email": email, "paste_count": 0, "pastes": [], "status": "clean"}
            raise
