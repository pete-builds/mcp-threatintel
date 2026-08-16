"""Regression tests for the container healthcheck probe.

Three bugs are pinned here. All three shipped to a running container at least
once, and none of them turns the healthcheck red, so nothing else catches them.

1. The probe leaked an MCP transport session on every call. Any request that
   reaches the ``/mcp`` mount mints a transport session before method dispatch,
   and nothing reaps it: roughly 40 kB per probe, which at the 30s HEALTHCHECK
   interval is about 2.9 GiB/month of unreclaimable growth. The fix is a probe
   path outside the mount, which is the default in pete-mcp-core as of commit
   6bf0ceb. A green healthcheck is not evidence either way.

2. The pete-mcp-core pin drifted between the manifests that carry it. Fixing
   one file and not the other looked like a fix and was not. requirements.lock
   is generated from pyproject.toml precisely so the two cannot disagree, and
   these tests assert that rather than trusting the generator.

3. The pin was a *stale* full SHA that predated the fix in (1), so adopting
   pete-mcp-core did not adopt the fixed healthcheck. The version floor test
   below asserts the installed package actually carries the session-free
   default rather than trusting the SHA string.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from pete_mcp_core.healthcheck import (
    DEFAULT_HEALTH_PATH,
    DEFAULT_HEALTHY_CODES,
    TRANSPORT_PATHS,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIM = REPO_ROOT / "src" / "mcp_threatintel" / "healthcheck.py"
SERVER_DEFAULT_PORT = 3707

#: Files that could pin pete-mcp-core. Every one of them must agree.
PIN_MANIFESTS = ("pyproject.toml", "requirements.lock")

_PIN_RE = re.compile(
    r"pete-mcp-core/archive/(?P<ref>[^/]+?)\.tar\.gz",
)


def _pins(name: str) -> list[str]:
    path = REPO_ROOT / name
    if not path.is_file():
        return []
    return [m.group("ref") for m in _PIN_RE.finditer(path.read_text())]


def test_core_pin_is_declared_in_every_manifest() -> None:
    """A manifest that silently omits the pin is how the fix half-lands."""
    missing = [name for name in PIN_MANIFESTS if not _pins(name)]
    assert not missing, f"pete-mcp-core pin missing from: {missing}"


def test_core_pin_agrees_across_manifests() -> None:
    found = {name: _pins(name) for name in PIN_MANIFESTS}
    refs = {ref for refs in found.values() for ref in refs}
    assert len(refs) == 1, f"pete-mcp-core pin has drifted across manifests: {found}"


def test_core_pin_is_an_immutable_full_commit_sha() -> None:
    """A branch or tag tarball is mutable, so it is not a pin at all."""
    for name in PIN_MANIFESTS:
        for ref in _pins(name):
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"{name} pins pete-mcp-core to {ref!r}, which is not a full "
                "40-character commit SHA. Branch and tag tarballs are mutable."
            )


def test_default_probe_path_is_outside_the_transport_mount() -> None:
    """This is the leak. /mcp, /sse and their trailing-slash forms all leak."""
    assert DEFAULT_HEALTH_PATH not in TRANSPORT_PATHS
    assert not DEFAULT_HEALTH_PATH.startswith(("/mcp", "/sse"))


def test_sentinel_404_counts_as_healthy() -> None:
    """The session-free probe hits an unrouted path, so Starlette answers 404.

    The pre-6bf0ceb code set was {200, 400, 405, 406}. Adopting the sentinel
    path without this code would have made every container permanently
    unhealthy, so the two changes have to land together.
    """
    assert 404 in DEFAULT_HEALTHY_CODES
    assert 500 not in DEFAULT_HEALTHY_CODES, "a genuine fault must still fail"


def test_shim_passes_the_servers_own_default_port() -> None:
    """Without this the probe falls back to the core default port, not ours."""
    source = SHIM.read_text()
    assert f"main(default_port={SERVER_DEFAULT_PORT})" in source


@pytest.mark.parametrize("name", ["Dockerfile", "docker-compose.yml"])
def test_container_does_not_pin_the_probe_back_onto_the_mount(name: str) -> None:
    """A leftover MCP_HEALTH_PATH=/mcp keeps the leak alive past the fix.

    The fixed core warns and reaps the session, which cuts the leak by about
    90% but does not eliminate it. Setting the variable at all is the bug.
    """
    text = (REPO_ROOT / name).read_text()
    assert "MCP_HEALTH_PATH" not in text, (
        f"{name} sets MCP_HEALTH_PATH. Leave it unset so the probe uses the "
        f"session-free default ({DEFAULT_HEALTH_PATH})."
    )
