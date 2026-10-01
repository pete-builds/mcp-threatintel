"""Streamable-http sessions must expire when idle.

FastMCP 4 quietly disarmed pete-mcp-core's session reaper. The reaper only
fills in ``session_idle_timeout`` when the caller passes none, and FastMCP 4
always passes one, explicitly None. Nothing errors and nothing logs: the
manager just never reaps, which is the ~40 kB per abandoned session leak the
reaper exists to stop. ``apply_session_idle_timeout`` restores it through
FastMCP 4's own setting.

If the control test starts failing, FastMCP has fixed this upstream: delete
``apply_session_idle_timeout`` and this file together.
"""

from __future__ import annotations

import asyncio
import os
import tempfile

import fastmcp
import pytest

os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "mcp_threatintel_test.db"))

from mcp_threatintel import server  # noqa: E402


def _manager_timeout() -> float | None:
    app = server.mcp.http_app(transport="streamable-http")

    async def read() -> float | None:
        async with app.router.lifespan_context(app):
            (route,) = [r for r in app.routes if getattr(r, "path", None) == "/mcp"]
            return route.endpoint.session_manager.session_idle_timeout

    return asyncio.run(read())


@pytest.fixture
def unset(monkeypatch):
    monkeypatch.delenv("MCP_SESSION_IDLE_TIMEOUT", raising=False)
    monkeypatch.setattr(fastmcp.settings, "http_session_idle_timeout", None)


def test_sessions_get_the_default_idle_timeout(unset):
    assert server.apply_session_idle_timeout() == 1800
    assert _manager_timeout() == 1800


def test_env_override_is_honored(unset, monkeypatch):
    monkeypatch.setenv("MCP_SESSION_IDLE_TIMEOUT", "600")
    assert server.apply_session_idle_timeout() == 600
    assert _manager_timeout() == 600


def test_control_without_the_fix_sessions_never_expire(unset):
    """Positive control: proves the assertions above can fail."""
    assert _manager_timeout() is None


def test_main_applies_it_before_serving(unset, monkeypatch):
    """The entry point, not just the helper: a dropped call in main() fails here."""
    seen = {}

    def fake_run_server(mcp, **kwargs):
        seen["timeout"] = fastmcp.settings.http_session_idle_timeout

    monkeypatch.setattr(server, "run_server", fake_run_server)
    server.main()
    assert seen == {"timeout": 1800}
