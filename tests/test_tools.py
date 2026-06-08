"""Tool smoke tests: exercise the MCP tool functions end-to-end against a
temp DB (DB_PATH is set by conftest.py before the server is imported).

The server module's @mcp.tool() decorator wraps each function; we call the
underlying coroutine via .fn to invoke the real logic without an MCP client.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel import db, server  # noqa: E402


def _call(tool):
    """Return the underlying coroutine function behind a FastMCP tool object."""
    return getattr(tool, "fn", tool)


def _seed_ioc():
    with db.connect(server.DB_PATH) as conn:
        db.upsert_ioc(
            conn,
            indicator="9.9.9.9",
            type="ip",
            source="threatfox",
            first_seen=None,
            last_seen=db._now(),
            tags="botnet",
            confidence=90,
            malware_family="qakbot",
            threat_type="c2",
            raw_json="{}",
        )
        conn.commit()


@pytest.mark.asyncio
async def test_lookup_ioc_finds_seeded_indicator():
    _seed_ioc()
    out = json.loads(await _call(server.lookup_ioc)("9.9.9.9"))
    assert out["indicator"] == "9.9.9.9"
    assert out["match_count"] == 1
    assert out["matches"][0]["source"] == "threatfox"
    # raw_json is stripped from responses.
    assert "raw_json" not in out["matches"][0]


@pytest.mark.asyncio
async def test_lookup_ioc_clean_for_unknown():
    out = json.loads(await _call(server.lookup_ioc)("203.0.113.255"))
    assert out["match_count"] == 0
    assert out["matches"] == []


@pytest.mark.asyncio
async def test_check_breach_without_key_returns_error_envelope(monkeypatch):
    # Force the unconfigured path regardless of local env.
    monkeypatch.setattr(server, "_leakcheck", None)
    out = json.loads(await _call(server.check_breach)("test@example.com"))
    assert "error" in out
    assert "LeakCheck" in out["error"]
