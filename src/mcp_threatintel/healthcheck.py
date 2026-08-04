"""Health check script for Docker HEALTHCHECK.

Thin shim over ``pete_mcp_core.healthcheck`` so the existing container
directive (``python -m mcp_threatintel.healthcheck``) keeps working.
"""

from pete_mcp_core.healthcheck import main

if __name__ == "__main__":
    main()
