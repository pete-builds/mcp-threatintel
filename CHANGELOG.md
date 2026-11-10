# Changelog

Notable changes to mcp-threatintel. Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version
is 0.x, a minor bump can carry a breaking change, and this file says so first.

## 0.4.0 (2026-11-09)

### Breaking

- **The server now refuses to start over HTTP without a bearer token.** Up to
  0.3.0 a server with no token ran anyway and answered every request on its
  port, authenticated or not. From 0.4.0, with no token set, the server
  container exits at startup with `Bearer token required for client
  'threatintel' but not provided` and never opens the port.

  What you must do before starting 0.4.0:

  1. Generate a token:
     `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
  2. Put it in `.env` on the host as `MCP_AUTH_TOKEN=<token>` and run
     `chmod 600 .env`. Do not put it in `docker-compose.yml` or in git.
  3. Add `Authorization: Bearer <token>` to every MCP client that connects.

  If step 2 is skipped, the server container restarts in a loop and the tools
  are unavailable until the token is set. If step 3 is skipped, the server runs
  and that client gets `401 Unauthorized`.

  There is no setting that turns this off for HTTP. `MCP_AUTH_REQUIRED=false`
  does not open the port: the server then exits with `Refusing to start
  streamable-http with no auth provider`.

### Changed

- `MCP_AUTH_TOKEN` is now the documented name for the token.
  `MCP_THREATINTEL_AUTH_TOKEN` is still accepted and still wins when both are
  set, exactly as before.
- `.env.example` ships `MCP_AUTH_TOKEN=` blank instead of a commented
  placeholder, so a copied example refuses to start rather than run with a
  token that is published in this repository.
- pete-mcp-core moves from commit `60cc81e` to `18f2261`, which is where the
  refusal comes from. It also carries session reaping fixes.

### Not affected

- **stdio.** `MCP_TRANSPORT=stdio` needs no token and nothing else new.
- **The poller container.** It needs no token and never reads the variable.
- **The container healthcheck.** It probes a path outside `/mcp` with no token
  and stays healthy with auth on.

### Also in this release

Already on `main` since 0.3.0 and first published in this version:

- Migrated to FastMCP 4 and MCP SDK 2 (#37).
- All 12 tools declare read-only annotations, and whether they call an
  external service (#29).
- `search_threats` and the other full-text tools run safe FTS5 queries, and
  time-window filtering is consistent across tools (#45).
- `search_darkweb` reports Ahmia being unavailable explicitly instead of
  returning an empty result (#44).
- The image patches base-image OS packages at build time (#27).
- Routine dependency and lockfile refreshes.

## 0.3.0 and earlier

See the git tags (`v0.3.0`, `v0.2.1`, `v0.2.0`) and the commit history.
