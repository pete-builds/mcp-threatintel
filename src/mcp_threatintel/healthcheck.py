"""Health check script for Docker HEALTHCHECK.

Thin shim over ``pete_mcp_core.healthcheck`` so the existing container
directive (``python -m mcp_threatintel.healthcheck``) keeps working. Passes
this server's own default port (3707) so a container running without
FASTMCP_PORT/MCP_PORT set still probes the port the server actually binds.

Deliberately sets no path. The core default is an unrouted liveness sentinel
outside the MCP mount, which is the only probe that does not create a
transport session per call. Do not reintroduce ``MCP_HEALTH_PATH=/mcp``:
every request that reaches the mount mints a session before method dispatch
and nothing reaps it, which leaked roughly 40 kB per probe here.
"""

from pete_mcp_core.healthcheck import main

if __name__ == "__main__":
    main(default_port=3707)
