"""Health check script for Docker HEALTHCHECK."""

import sys
import urllib.request


def check():
    try:
        resp = urllib.request.urlopen("http://localhost:3707/sse", timeout=5)
        if resp.status == 200:
            sys.exit(0)
    except Exception:
        pass
    sys.exit(1)


if __name__ == "__main__":
    check()
