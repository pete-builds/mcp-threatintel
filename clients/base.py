"""Base HTTP client with retry and rate limiting."""

import asyncio
import time

import httpx


class BaseClient:
    """Async HTTP client with rate limiting and one retry on connection errors."""

    def __init__(self, base_url: str, headers: dict | None = None, rate_limit: float = 1.0):
        self.base_url = base_url.rstrip("/")
        self._rate_limit_delay = rate_limit
        self._last_request_time = 0.0
        default_headers = {"User-Agent": "mcp-threatintel/1.0"}
        if headers:
            default_headers.update(headers)
        self._client = httpx.AsyncClient(
            timeout=30,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            headers=default_headers,
        )

    async def _rate_limit(self):
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.monotonic()

    async def get(self, path: str, params: dict | None = None) -> dict | list:
        await self._rate_limit()
        url = f"{self.base_url}{path}"
        for attempt in range(2):
            try:
                resp = await self._client.get(url, params=params)
                resp.raise_for_status()
                return resp.json()
            except (httpx.RemoteProtocolError, httpx.ConnectError):
                if attempt == 0:
                    continue
                raise

    async def post(self, path: str, data: dict | None = None, json_data: dict | None = None) -> dict | list:
        await self._rate_limit()
        url = f"{self.base_url}{path}"
        for attempt in range(2):
            try:
                resp = await self._client.post(url, data=data, json=json_data)
                resp.raise_for_status()
                return resp.json()
            except (httpx.RemoteProtocolError, httpx.ConnectError):
                if attempt == 0:
                    continue
                raise

    async def close(self):
        await self._client.aclose()
