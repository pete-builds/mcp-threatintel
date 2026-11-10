"""Pytest fixtures: point the server at a throwaway DB before it is imported."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# The server module creates the schema at import time from DB_PATH. Point it at
# a temp file so importing it never touches /data or a real cache. Set before
# any test imports mcp_threatintel.server.
_TMP_DB = os.path.join(tempfile.gettempdir(), "mcp_threatintel_test.db")
os.environ.setdefault("DB_PATH", _TMP_DB)

# The server module also builds its auth provider at import time, and over HTTP
# (its default transport) it refuses to load without a bearer token. Give the
# suite an explicit fake one, so the module every test imports has the shape a
# deployment has: auth on. Never inherit this from the calling shell. Tests
# that need another configuration reload the module under their own
# environment (see test_auth_required.py).
for _name in ("MCP_THREATINTEL_AUTH_TOKEN", "MCP_AUTH_REQUIRED", "MCP_TRANSPORT"):
    os.environ.pop(_name, None)
os.environ["MCP_AUTH_TOKEN"] = "test-token-not-a-secret"
