"""Health check script for Docker HEALTHCHECK.

Thin shim over ``pete_mcp_core.healthcheck`` so the existing container
directive (``python -m mcp_threatintel.healthcheck``) keeps working. Passes
this server's own default port (3707) so a container running without
FASTMCP_PORT/MCP_PORT set still probes the port the server actually binds.
"""

from pete_mcp_core.healthcheck import main

if __name__ == "__main__":
    main(default_port=3707)
