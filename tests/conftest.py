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
