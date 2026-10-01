FROM python:3.13-slim AS builder

WORKDIR /build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencies come from the hash-pinned lockfile, so every transitive wheel
# (including the pete-mcp-core commit tarball) is verified against a recorded
# sha256 and an unexpected artifact fails the build instead of shipping.
#
# The lockfile is generated FROM pyproject.toml, which stays the only place a
# version or a pin is edited by hand. Regenerate with:
#   uv pip compile pyproject.toml -o requirements.lock \
#     --generate-hashes --universal --python-version 3.13
# CI fails the build if the lockfile has drifted from pyproject.toml.
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock

# Then the package itself (src layout), with --no-deps: the lockfile above
# already provided the full dependency closure, and re-resolving here would
# bypass the hashes.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps --prefix=/install .

FROM python:3.13-slim

# Patch OS packages carried by the base image. The python:3.13-slim tag lags the Debian
# security archive, so a scan flags CVEs that are already fixed upstream but that no
# application or lockfile change can reach. Upgrading here pulls the patched packages in
# at build time, and keeps doing so for future base-image CVEs.
#
# Currently clears CVE-2026-53615 (util-linux 2.41-5 -> 2.41.5-0+deb13u1). Trivy reports
# it 9 times, once per util-linux binary package (bsdutils, libblkid1, libmount1, login,
# and the rest), but it is a single source-package fix.
#
# The ADD busts the build cache whenever Debian publishes a security update. A RUN layer
# is keyed only on its command string, which never changes, so with `cache-from:
# type=gha` CI would otherwise replay the first day's upgrade forever and miss every
# later fix. buildkit keys ADD on the remote file's content, not its URL.
ADD https://deb.debian.org/debian-security/dists/trixie-security/Release /tmp/debian-security-release
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /tmp/debian-security-release /var/lib/apt/lists/*

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Non-root user with pinned UID/GID 1000. The /data volume is chowned so the
# poller and server can write the SQLite cache without running as root.
RUN groupadd --system --gid 1000 mcp \
    && useradd --system --uid 1000 --gid 1000 --no-create-home --shell /usr/sbin/nologin mcp \
    && mkdir -p /data \
    && chown -R mcp:mcp /data /app

COPY --from=builder /install /usr/local

# Drop pip from the runtime image. Nothing at runtime uses it: dependencies are copied
# into /usr/local from the builder stage, already installed.
#
# This is also the only fix for two recurring Trivy HIGHs. pip ships a vendored
# dependency set (see pip/_vendor/vendor.txt) that Trivy scans as real packages:
# msgpack 1.1.2 (GHSA-6v7p-g79w-8964) and setuptools 70.3.0 (CVE-2025-47273).
# Neither is an application dependency, so no lockfile change can move them, and
# no pip release ships fixed versions. Removing the unused component is the fix.
RUN python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.*/site-packages/pip \
              /usr/local/lib/python3.*/site-packages/pip-*.dist-info \
              /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.*

# FastMCP 4 phones PyPI on every start (GET https://pypi.org/pypi/fastmcp/json)
# to print an update notice in the banner. Nothing in the container acts on it.
ENV FASTMCP_CHECK_FOR_UPDATES=off

USER mcp

EXPOSE 3707

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-m", "mcp_threatintel.healthcheck"]

CMD ["mcp-threatintel"]
