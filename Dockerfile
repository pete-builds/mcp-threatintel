FROM python:3.13-slim AS builder

WORKDIR /build

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install the package (src layout) into an isolated prefix.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.13-slim

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

USER mcp

EXPOSE 3707

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-m", "mcp_threatintel.healthcheck"]

CMD ["mcp-threatintel"]
