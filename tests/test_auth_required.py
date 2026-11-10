"""HTTP needs a bearer token. Without one this server does not start.

Until pete-mcp-core 18f2261 this server ran on the LAN with no token and
answered every unauthenticated request with 200. A missing token logged one
warning into a JSON log nobody reads and carried on, which is the same as no
warning at all. From 18f2261 the library refuses instead, and these tests pin
that against THIS server's real module, its real ASGI app and its real entry
points, not against the library in isolation.

There are two locks, and each has its own test so that removing either one
turns something here red:

1. ``build_auth_provider(..., required=True)`` raises ``AuthRequiredError``
   while the server module loads.
2. ``run_server()`` refuses streamable-http when ``mcp.auth`` is None. This is
   what still holds if someone sets ``MCP_AUTH_REQUIRED=false``.

What is deliberately NOT gated, each with a test for the reason:

- The container healthcheck. It probes an unrouted path with no token, and if
  that probe went unhealthy under auth the container would flap forever.
- stdio. It is a local pipe with no network surface.
- The poller. It is a second container on the same image, and it must keep
  starting with no token in its environment.

Every token below is an obviously fake string. Nothing here reaches a network
beyond loopback.
"""

from __future__ import annotations

import contextlib
import importlib
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from types import ModuleType

import dotenv
import fastmcp
import httpx
import pytest
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from pete_mcp_core.auth import AuthRequiredError
from pete_mcp_core.healthcheck import (
    DEFAULT_HEALTH_PATH,
    DEFAULT_HEALTHY_CODES,
    TRANSPORT_PATHS,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = "mcp_threatintel.server"
PACKAGE = "mcp_threatintel"

TOKEN = "test-token-not-a-secret"
OTHER_TOKEN = "other-token-not-a-secret"
WRONG_TOKEN = "wrong-token-not-a-secret"

#: Every environment variable the server accepts the token under. Read off the
#: settings field in ``test_the_accepted_token_names_are_the_ones_covered_here``,
#: so adding an alias without covering it here fails.
CANONICAL_TOKEN_VAR = "MCP_AUTH_TOKEN"
LEGACY_TOKEN_VAR = "MCP_THREATINTEL_AUTH_TOKEN"
TOKEN_VARS = (CANONICAL_TOKEN_VAR, LEGACY_TOKEN_VAR)

#: Everything that decides whether auth is on. Cleared before every scenario so
#: nothing leaks in from conftest or from the calling shell.
AUTH_ENV = (*TOKEN_VARS, "MCP_AUTH_REQUIRED", "MCP_TRANSPORT")

REFUSED_AT_LOAD = "Bearer token required for client 'threatintel'"
REFUSED_AT_SERVE = "Refusing to start streamable-http with no auth provider"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "auth-required-test", "version": "0"},
    },
}
MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


@pytest.fixture
def load_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[Callable[..., ModuleType]]:
    """Import a fresh copy of the real server module under a chosen environment.

    The module reads its settings and builds its auth provider at import time,
    so the only honest way to test another configuration is to import it again.
    The copy the rest of the suite holds is put back afterwards.
    """
    package = importlib.import_module(PACKAGE)
    original = sys.modules.get(MODULE)

    for name in AUTH_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "threatintel.db"))
    # No .env may answer for the environment: not one in the working directory
    # (pydantic-settings) and not one found by walking up from the source tree
    # (python-dotenv). A developer's real token must not make these pass.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dotenv, "load_dotenv", lambda *args, **kwargs: False)
    # main() arms the session reaper, which patches the SDK class and may set a
    # FastMCP setting for the whole process. Record both so they are undone.
    current = StreamableHTTPSessionManager.__init__
    monkeypatch.setattr(StreamableHTTPSessionManager, "__init__", current)
    monkeypatch.setattr(
        fastmcp.settings,
        "http_session_idle_timeout",
        fastmcp.settings.http_session_idle_timeout,
    )

    def _load(**env: str) -> ModuleType:
        for name, value in env.items():
            monkeypatch.setenv(name, value)
        sys.modules.pop(MODULE, None)
        return importlib.import_module(MODULE)

    yield _load

    sys.modules.pop(MODULE, None)
    if original is not None:
        sys.modules[MODULE] = original
        package.server = original


@contextlib.asynccontextmanager
async def _http_client(server: ModuleType) -> AsyncIterator[httpx.AsyncClient]:
    """The server's real streamable-http app, in process, with its lifespan run."""
    app = server.mcp.http_app(transport="streamable-http")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:3707"
        ) as client:
            yield client


async def _initialize(client: httpx.AsyncClient, authorization: str | None) -> httpx.Response:
    headers = dict(MCP_HEADERS)
    if authorization is not None:
        headers["Authorization"] = authorization
    return await client.post("/mcp", json=INITIALIZE, headers=headers)


def _result(response: httpx.Response) -> dict:
    """The JSON-RPC result of an initialize response, JSON or SSE framed."""
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        (payload,) = [
            line.removeprefix("data:").strip()
            for line in response.text.splitlines()
            if line.startswith("data:")
        ]
        message = json.loads(payload)
    else:
        message = response.json()
    assert "error" not in message, message
    return message["result"]


def _clean_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """A subprocess environment in which nothing but ``extra`` decides auth."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in AUTH_ENV
        and k not in {"FASTMCP_HOST", "MCP_HOST", "FASTMCP_PORT", "MCP_PORT"}
        and not k.startswith(("FASTMCP_HTTP_", "MCP_AUTH", "MCP_HEALTH"))
    }
    env.update(
        {
            "DB_PATH": str(tmp_path / "threatintel.db"),
            "FASTMCP_CHECK_FOR_UPDATES": "off",
            "FASTMCP_SHOW_SERVER_BANNER": "false",
            # python-dotenv walks up from the source tree looking for a .env.
            "PYTHON_DOTENV_DISABLED": "1",
        }
    )
    env.update(extra)
    return env


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextlib.contextmanager
def _serve(tmp_path: Path, **extra: str) -> Iterator[int]:
    """Boot the real entry point, exactly as the container does, on a free port."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", MODULE],
        env=_clean_env(tmp_path, FASTMCP_PORT=str(port), **extra),
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                pytest.fail(f"server exited early ({proc.returncode}):\n{err[-2000:]}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.fail("server did not start listening within 30s")
                time.sleep(0.1)
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _probe(port: int, tmp_path: Path) -> int:
    """Run the container's own HEALTHCHECK command and return its exit code."""
    return subprocess.run(
        [sys.executable, "-m", "mcp_threatintel.healthcheck"],
        env=_clean_env(tmp_path, FASTMCP_PORT=str(port)),
        cwd=tmp_path,
        capture_output=True,
        timeout=30,
    ).returncode


# ---------------------------------------------------------------------------
# Lock 1: no token, no module
# ---------------------------------------------------------------------------


def test_http_without_a_token_refuses_to_load(load_server) -> None:
    """The default transport is streamable-http, so this is a bare container."""
    with pytest.raises(AuthRequiredError, match=REFUSED_AT_LOAD):
        load_server()


def test_explicit_http_without_a_token_refuses_to_load(load_server) -> None:
    with pytest.raises(AuthRequiredError, match=REFUSED_AT_LOAD):
        load_server(MCP_TRANSPORT="streamable-http")


@pytest.mark.parametrize("name", TOKEN_VARS)
@pytest.mark.parametrize("blank", ["", "   "], ids=["empty", "whitespace"])
def test_a_blank_token_is_no_token(load_server, name: str, blank: str) -> None:
    """``.env.example`` ships the variable empty. Copied as is, that must refuse."""
    with pytest.raises(AuthRequiredError, match=REFUSED_AT_LOAD):
        load_server(**{name: blank})


def test_the_accepted_token_names_are_the_ones_covered_here(load_server) -> None:
    """A new alias on the settings field must be added to TOKEN_VARS above."""
    server = load_server(**{CANONICAL_TOKEN_VAR: TOKEN})
    field = server.ThreatIntelSettings.model_fields["threatintel_auth_token"]
    assert set(field.validation_alias.choices) == set(TOKEN_VARS)


# ---------------------------------------------------------------------------
# Lock 2: no auth provider, no listener
# ---------------------------------------------------------------------------


def test_auth_required_false_still_cannot_serve_http(load_server, monkeypatch) -> None:
    """MCP_AUTH_REQUIRED=false skips lock 1. run_server must still refuse.

    This is the test that goes red if ``allow_unauthenticated=True`` is ever
    passed to run_server, which is the one-line change that would put this
    server back on the LAN with no token.
    """
    server = load_server(MCP_AUTH_REQUIRED="false")
    assert server.mcp.auth is None, "this scenario needs a server with no auth provider"

    def would_have_served(*args: object, **kwargs: object) -> None:
        pytest.fail(f"server started serving with no auth provider: {kwargs}")

    monkeypatch.setattr(server.mcp, "run", would_have_served)
    with pytest.raises(ValueError, match=REFUSED_AT_SERVE):
        server.main()


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({}, REFUSED_AT_LOAD),
        ({"MCP_AUTH_REQUIRED": "false"}, REFUSED_AT_SERVE),
    ],
    ids=["no-token", "no-token-auth-required-false"],
)
def test_the_real_entry_point_exits_nonzero_without_a_token(
    tmp_path: Path, extra: dict[str, str], expected: str
) -> None:
    """What the container runs. It must die with the reason, not listen."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", MODULE],
        env=_clean_env(tmp_path, FASTMCP_PORT=str(port), **extra),
        cwd=tmp_path,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _, err = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("server was still running after 30s with no token: it did not refuse")
    assert proc.returncode != 0
    assert expected in err.decode(errors="replace")


# ---------------------------------------------------------------------------
# With a token: the real ASGI app turns away everyone who does not present it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", TOKEN_VARS)
async def test_initialize_without_a_header_is_401(load_server, name: str) -> None:
    server = load_server(**{name: TOKEN})
    async with _http_client(server) as client:
        response = await _initialize(client, None)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")
    assert "mcp-session-id" not in response.headers, "a refused request minted a session"


@pytest.mark.parametrize("name", TOKEN_VARS)
@pytest.mark.parametrize(
    "authorization",
    [f"Bearer {WRONG_TOKEN}", TOKEN, f"Basic {TOKEN}", "Bearer "],
    ids=["wrong-token", "no-scheme", "wrong-scheme", "empty-bearer"],
)
async def test_initialize_with_a_bad_credential_is_401(
    load_server, name: str, authorization: str
) -> None:
    server = load_server(**{name: TOKEN})
    async with _http_client(server) as client:
        response = await _initialize(client, authorization)
    assert response.status_code == 401
    assert "mcp-session-id" not in response.headers


@pytest.mark.parametrize("name", TOKEN_VARS)
async def test_initialize_with_the_token_succeeds(load_server, name: str) -> None:
    server = load_server(**{name: TOKEN})
    async with _http_client(server) as client:
        response = await _initialize(client, f"Bearer {TOKEN}")
        assert response.status_code != 401
        assert response.status_code == 200
        result = _result(response)
        assert result["serverInfo"]["name"] == "ThreatIntel"
        assert result["protocolVersion"]
        assert response.headers["mcp-session-id"]


async def test_the_legacy_name_wins_when_both_are_set(load_server) -> None:
    """Documented in the README, so it is pinned: one token is live, not two."""
    server = load_server(**{LEGACY_TOKEN_VAR: TOKEN, CANONICAL_TOKEN_VAR: OTHER_TOKEN})
    async with _http_client(server) as client:
        assert (await _initialize(client, f"Bearer {TOKEN}")).status_code == 200
        assert (await _initialize(client, f"Bearer {OTHER_TOKEN}")).status_code == 401


# ---------------------------------------------------------------------------
# The healthcheck stays healthy with auth on and no token presented
# ---------------------------------------------------------------------------


def _probed_path() -> str:
    """The path the container HEALTHCHECK requests, resolved the way the core does.

    The shim passes no path and neither the Dockerfile nor the compose file sets
    MCP_HEALTH_PATH (test_healthcheck.py pins that), so it is the core default.
    """
    shim = (REPO_ROOT / "src" / PACKAGE / "healthcheck.py").read_text()
    assert "main(default_port=3707)" in shim
    return DEFAULT_HEALTH_PATH


def test_the_probed_path_is_not_a_transport_path() -> None:
    probed = _probed_path()
    assert probed not in TRANSPORT_PATHS
    assert not probed.startswith(("/mcp", "/sse"))


@pytest.mark.parametrize("name", TOKEN_VARS)
async def test_unauthenticated_probe_is_healthy_by_the_healthchecks_own_rules(
    load_server, name: str
) -> None:
    server = load_server(**{name: TOKEN})
    async with _http_client(server) as client:
        response = await client.get(_probed_path())
    assert response.status_code in DEFAULT_HEALTHY_CODES
    assert response.status_code != 500
    assert "mcp-session-id" not in response.headers, "the probe minted a transport session"


def test_the_container_healthcheck_command_passes_against_an_authenticated_server(
    tmp_path: Path,
) -> None:
    """End to end: the real server with auth on, and the real HEALTHCHECK command.

    The probe carries no token. The closed-port control proves the command can
    report unhealthy, so the 0 above it is evidence and not a constant.
    """
    with _serve(tmp_path, **{CANONICAL_TOKEN_VAR: TOKEN}) as port:
        assert _probe(port, tmp_path) == 0
    assert _probe(_free_port(), tmp_path) == 1


# ---------------------------------------------------------------------------
# stdio: local development needs no token
# ---------------------------------------------------------------------------


def test_stdio_loads_without_a_token(load_server) -> None:
    server = load_server(MCP_TRANSPORT="stdio")
    assert server.mcp.auth is None


def test_stdio_answers_initialize_without_a_token(tmp_path: Path) -> None:
    """The real entry point on stdio, with nothing set but the transport."""
    proc = subprocess.Popen(
        [sys.executable, "-m", MODULE],
        env=_clean_env(tmp_path, MCP_TRANSPORT="stdio"),
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        out, err = proc.communicate(input=json.dumps(INITIALIZE).encode() + b"\n", timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        pytest.fail("stdio server did not answer and exit within 30s")
    lines = [line for line in out.decode().splitlines() if line.strip()]
    assert lines, f"no reply on stdout. stderr:\n{err.decode(errors='replace')[-2000:]}"
    reply = json.loads(lines[0])
    assert reply["id"] == 1
    assert reply["result"]["serverInfo"]["name"] == "ThreatIntel"


# ---------------------------------------------------------------------------
# The poller: same image, second container, no token
# ---------------------------------------------------------------------------

_POLLER_DRIVER = textwrap.dedent(
    """
    import sys

    import httpx

    from mcp_threatintel.clients.base import BaseClient


    async def no_network(*args, **kwargs):
        raise RuntimeError("network disabled in tests")


    # Cut every route to an upstream before the poller is imported.
    BaseClient.get = no_network
    BaseClient.post = no_network
    httpx.AsyncClient.send = no_network

    from mcp_threatintel import poller

    sys.argv = ["mcp-threatintel-poller"]
    poller.main()

    loaded = sorted(
        name
        for name in ("mcp_threatintel.server", "pete_mcp_core", "fastmcp")
        if name in sys.modules
    )
    print("POLLER_OK loaded=" + ",".join(loaded))
    """
)


def test_poller_starts_and_completes_a_cycle_without_a_token(tmp_path: Path) -> None:
    """The poller container gets no token and must not need one.

    Runs the poller's real ``main()`` for one cycle with every upstream call cut
    off, in an environment with no token and the default (HTTP) transport: the
    exact conditions under which the server refuses to start. It also asserts
    the poller never imports the server module or pete-mcp-core, because that
    import is the only way the token requirement could ever reach it.
    """
    result = subprocess.run(
        [sys.executable, "-c", _POLLER_DRIVER],
        env=_clean_env(tmp_path),
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "POLLER_OK loaded=\n" in result.stdout, (
        "the poller imported the server stack, so it now inherits the token "
        f"requirement: {result.stdout!r}"
    )
    assert "Poll cycle complete" in result.stderr
    assert (tmp_path / "threatintel.db").is_file()


# ---------------------------------------------------------------------------
# The documents must not hand out a working token
# ---------------------------------------------------------------------------


def test_env_example_ships_the_token_blank() -> None:
    """A placeholder value here would be a token the whole internet knows.

    Anyone who copied the example and started the server would be running with
    it. Blank is the only safe example: it refuses to start until filled in.
    """
    assigned = {}
    for line in (REPO_ROOT / ".env.example").read_text().splitlines():
        stripped = line.lstrip("# ").strip()
        for name in TOKEN_VARS:
            if stripped.startswith(f"{name}="):
                assigned[name] = stripped.partition("=")[2].strip()
    assert CANONICAL_TOKEN_VAR in assigned, ".env.example must show where the token goes"
    assert all(value == "" for value in assigned.values()), assigned


def test_compose_never_carries_the_token() -> None:
    """The token belongs in .env on the host, never in a file that is in git."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    for line in compose.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for name in TOKEN_VARS:
            assert name not in line, f"docker-compose.yml sets {name}: {line.strip()!r}"
