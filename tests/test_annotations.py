"""Every tool declares itself read-only, and says whether it opens a socket.

Twelve tools, all lookups, and not one writes anything a caller can observe.
That is worth declaring rather than leaving to be inferred: an unannotated
read-only server and an unannotated server full of delete tools are
indistinguishable in the manifest.

THE OPEN-WORLD SPLIT IS EXACTLY HALF, and it is the part that had to be checked
rather than assumed. Six tools query the local SQLite cache and never open a
socket; the other six call LeakCheck, Ahmia, or HIBP. Marking all twelve
open-world would have been the easy uniform answer and would have been wrong
about half the surface. The cache is refreshed by a separate sync process, so
the DATA originates externally -- but these tools do not go and get it, and
that is what the hint describes.
"""

from __future__ import annotations

import asyncio

import pytest

from mcp_threatintel import server

#: Query the local SQLite cache. Verified by reading each body for a `connect`
#: call rather than inferred from the name -- `lookup_ioc` and `check_breach`
#: read alike and land on opposite sides.
LOCAL = {
    "lookup_ioc", "search_threats", "get_recent_threats", "lookup_cve",
    "get_feed_status", "search_pulses",
}
#: Call out to LeakCheck, Ahmia, or HIBP.
REMOTE = {
    "check_breach", "check_domain_breaches", "search_darkweb",
    "check_password_breach", "check_email_breaches", "get_latest_breach",
}


@pytest.fixture(scope="module")
def tools():
    """The live manifest, not the source. What a client would receive."""
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_the_expected_twelve_are_present(tools):
    """Guards the guard: an empty manifest would pass everything below."""
    assert set(tools) == LOCAL | REMOTE


def test_every_tool_is_annotated(tools):
    assert sorted(n for n, t in tools.items() if t.annotations is None) == []


def test_every_tool_is_read_only(tools):
    """A write tool added later fails here first, which is the point."""
    assert sorted(n for n, t in tools.items() if not t.annotations.readOnlyHint) == []


def test_nothing_claims_to_be_destructive(tools):
    assert sorted(n for n, t in tools.items() if t.annotations.destructiveHint) == []


def test_cache_backed_tools_do_not_claim_an_open_world(tools):
    wrong = sorted(n for n in LOCAL if tools[n].annotations.openWorldHint is not False)
    assert wrong == []


def test_feed_backed_tools_do(tools):
    wrong = sorted(n for n in REMOTE if tools[n].annotations.openWorldHint is not True)
    assert wrong == []


def test_the_split_is_not_collapsed_one_way(tools):
    """Guard against a classification bug that marks everything the same.

    Both directions must be non-empty, or the split is decorative.
    """
    open_world = {n for n, t in tools.items() if t.annotations.openWorldHint}
    assert open_world and open_world != set(tools)
