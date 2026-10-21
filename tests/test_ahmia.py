"""Ahmia client tests. No real network: httpx is driven by a MockTransport.

The contract under test: a real results page parses to results; anything
else (a redirect because the search-form token is missing, an HTTP error,
a transport failure, a page that is not a results page) comes back as an
explicit "unavailable" error and never as an empty result list.
"""

import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel.clients.ahmia import AhmiaClient  # noqa: E402

FIXTURE = (Path(__file__).parent / "fixtures" / "ahmia_results.html").read_text()

EMPTY_RESULTS_PAGE = """<html><body><div id="ahmiaResultsPage">
<div class="resultsSubheader"><p>Displaying
<span class="resultNumber" id="totalResults">0</span> matches</p></div>
<ol class="searchResults"></ol></div></body></html>"""

# What ahmia.fi/ serves: the search form with its hidden token, no results.
HOMEPAGE = """<html><body><form id="searchForm" action="/search/" method="get">
<input id="id_q" type="search" name="q">
<input type="hidden" name="b20114" value="81480f">
</form><a href="http://cccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion/">mirror</a>
</body></html>"""


def _client(handler) -> AhmiaClient:
    client = AhmiaClient()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client._rate_limit_delay = 0
    return client


def _assert_unavailable(data: dict, query: str) -> None:
    assert data["available"] is False
    assert data["query"] == query
    assert "unavailable" in data["error"].lower()
    # Must not look like a clean, empty search.
    assert "results" not in data
    assert "result_count" not in data


async def test_happy_path_parses_current_results_page():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, text=FIXTURE)

    data = await _client(handler).search("PHP", max_results=20)

    assert "q=PHP" in seen["url"]
    assert data["result_count"] == 2
    assert "available" not in data  # success shape is unchanged
    first, second = data["results"]
    assert first["title"] == "Example PHP forum"
    assert first["url"] == "http://" + "a" * 54 + ".onion/"
    assert first["description"] == "An example description of a PHP discussion board."
    assert second["url"] == "http://" + "b" * 54 + ".onion/paste/1"


async def test_max_results_caps_parsed_results():
    data = await _client(lambda r: httpx.Response(200, text=FIXTURE)).search("PHP", 1)
    assert data["result_count"] == 1


async def test_genuine_empty_results_page_is_zero_not_error():
    data = await _client(lambda r: httpx.Response(200, text=EMPTY_RESULTS_PAGE)).search("zzz")
    assert data["result_count"] == 0
    assert data["results"] == []
    assert "error" not in data


async def test_missing_token_redirect_reports_unavailable():
    """Ahmia 302s a search without its form token back to "/"."""
    calls = []

    def handler(request):
        calls.append(str(request.url))
        if request.url.path == "/search/":
            return httpx.Response(302, headers={"location": "/"})
        return httpx.Response(200, text=HOMEPAGE)

    data = await _client(handler).search("PHP")

    _assert_unavailable(data, "PHP")
    assert "302" in data["error"]
    assert "token" in data["error"]
    assert len(calls) == 1  # the redirect is not followed into the homepage


async def test_non_results_page_reports_unavailable():
    """A 200 that is not a results page (e.g. the homepage) is not "no hits"."""
    data = await _client(lambda r: httpx.Response(200, text=HOMEPAGE)).search("PHP")
    _assert_unavailable(data, "PHP")


@pytest.mark.parametrize("status", [403, 429, 500, 503])
async def test_http_error_reports_unavailable(status):
    data = await _client(lambda r: httpx.Response(status, text="nope")).search("PHP")
    _assert_unavailable(data, "PHP")
    assert str(status) in data["error"]


async def test_transport_failure_retries_once_then_reports_unavailable():
    attempts = []

    def handler(request):
        attempts.append(1)
        raise httpx.ConnectError("connection refused", request=request)

    data = await _client(handler).search("PHP")
    _assert_unavailable(data, "PHP")
    assert len(attempts) == 2


async def test_tool_returns_unavailable_json(monkeypatch):
    from mcp_threatintel import server

    monkeypatch.setattr(
        server,
        "_ahmia",
        _client(lambda r: httpx.Response(302, headers={"location": "/"})),
    )
    tool = getattr(server.search_darkweb, "fn", server.search_darkweb)
    data = json.loads(await tool("PHP"))
    _assert_unavailable(data, "PHP")
