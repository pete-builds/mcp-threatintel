"""The real listener must answer a LAN client, not just loopback.

This server is reached over the LAN at http://192.168.86.20:3707. MCP SDK 2
servers can answer every such client with HTTP 421 "Misdirected Request" or
"Invalid Host header" (DNS-rebinding protection keyed on a loopback bind),
while every unit test passes and a loopback healthcheck stays healthy. Nothing
else in CI would notice, so this boots the real entry point in a subprocess,
exactly as the container does, and sends an MCP initialize carrying a LAN
``Host`` header.

The control test builds the server the loopback way (bound to 127.0.0.1 with
FastMCP's host protection in "auto") and asserts it DOES answer 421. That
proves the harness can see the failure: if the control ever stops getting 421,
the main assertion is no longer evidence of anything.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator

import pytest

MODULE = "mcp_threatintel.server"
LAN_HOST = "192.168.86.20:3707"

INITIALIZE = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "lan-host-test", "version": "0"},
        },
    }
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _non_loopback_ip() -> str | None:
    """This machine's outbound interface address, or None if it only has loopback.

    A UDP connect sends no packet; it only asks the kernel which source address
    it would use. 192.0.2.1 is TEST-NET-1, never routed.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))
        except OSError:
            return None
        ip = s.getsockname()[0]
    return None if ip.startswith("127.") or ip == "0.0.0.0" else ip


@contextlib.contextmanager
def _serve(extra_env: dict[str, str] | None = None) -> Iterator[int]:
    port = _free_port()
    env = {
        k: v
        for k, v in os.environ.items()
        # Bind host, transport and auth come from the server's own defaults,
        # never from whatever the calling shell happens to export.
        if k not in {"FASTMCP_HOST", "MCP_HOST", "MCP_TRANSPORT", "MCP_THREATINTEL_AUTH_TOKEN"}
        and not k.startswith(("FASTMCP_HTTP_", "MCP_AUTH"))
    }
    env.update(
        {
            "DB_PATH": os.path.join(tempfile.mkdtemp(), "threatintel.db"),
            "FASTMCP_PORT": str(port),
            "FASTMCP_CHECK_FOR_UPDATES": "off",
            "FASTMCP_SHOW_SERVER_BANNER": "false",
        }
    )
    env.update(extra_env or {})
    proc = subprocess.Popen(
        [sys.executable, "-m", MODULE],
        env=env,
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


def _initialize(connect_to: str, port: int, host_header: str) -> int:
    conn = http.client.HTTPConnection(connect_to, port, timeout=10)
    try:
        conn.request(
            "POST",
            "/mcp",
            body=INITIALIZE,
            headers={
                "Host": host_header,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def test_lan_host_header_is_answered():
    with _serve() as port:
        status = _initialize("127.0.0.1", port, LAN_HOST)
    assert status != 421, "LAN Host header refused as misdirected: the 421 trap is back"
    assert status == 200, f"initialize with a LAN Host header returned {status}"


def test_listener_is_reachable_on_a_non_loopback_interface():
    """A loopback-only bind refuses this connection outright."""
    ip = _non_loopback_ip()
    if ip is None:
        pytest.skip("no non-loopback interface on this machine")
    with _serve() as port:
        status = _initialize(ip, port, LAN_HOST)
    assert status == 200, f"initialize over {ip} with a LAN Host header returned {status}"


def test_control_loopback_build_does_421():
    """Positive control: the loopback way MUST fail, or the tests above prove nothing."""
    with _serve(
        {"FASTMCP_HOST": "127.0.0.1", "FASTMCP_HTTP_HOST_ORIGIN_PROTECTION": "auto"}
    ) as port:
        assert _initialize("127.0.0.1", port, f"127.0.0.1:{port}") == 200
        assert _initialize("127.0.0.1", port, LAN_HOST) == 421
