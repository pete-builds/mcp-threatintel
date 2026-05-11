"""Health check script for Docker HEALTHCHECK.

Streamable HTTP exposes a single ``/mcp`` endpoint that responds to a bare
GET with HTTP 400/405/406 (the transport rejects non-streaming requests).
Treat that as healthy: it confirms the FastMCP server is listening and routing.
"""

import os
import sys
import urllib.error
import urllib.request

_HEALTHY_NON_OK_CODES: frozenset[int] = frozenset({400, 405, 406})


def check() -> int:
    port = os.getenv("FASTMCP_PORT", os.getenv("MCP_PORT", "3707"))
    url = f"http://localhost:{port}/mcp"
    try:
        resp = urllib.request.urlopen(url, timeout=5)  # noqa: S310 - localhost only
        return 0 if resp.status == 200 else 1
    except urllib.error.HTTPError as exc:
        return 0 if exc.code in _HEALTHY_NON_OK_CODES else 1
    except (urllib.error.URLError, OSError):
        return 1


if __name__ == "__main__":
    sys.exit(check())
