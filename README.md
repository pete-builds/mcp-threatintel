# mcp-threatintel

A threat intelligence MCP server for [Claude Code](https://claude.com/claude-code). Gives Claude tools to look up IOCs, search threat feeds, check breached credentials, query CVEs, and search the dark web.

Built with [FastMCP](https://github.com/jlowin/fastmcp) and SQLite. Feeds are synced locally by a background poller so lookups are fast and don't depend on external API availability.

---

## Tools

| Tool | What it does |
|------|-------------|
| `lookup_ioc` | Check an IP, domain, hash, or URL against all threat feeds |
| `search_threats` | Full-text search across IOCs, OTX pulses, and CVEs |
| `get_recent_threats` | What's been added in the last N hours |
| `lookup_cve` | Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog |
| `get_feed_status` | Show sync status and record counts for all feeds |
| `search_pulses` | Search AlienVault OTX community threat pulses |
| `check_breach` | Check LeakCheck for breached credentials by email, domain, username, or hash |
| `check_domain_breaches` | Check all known breaches for a domain |
| `search_darkweb` | Search Ahmia.fi's index of Tor hidden services |
| `check_password_breach` | Check if a password has been exposed (HIBP k-anonymity, free, password never leaves machine) |
| `check_email_breaches` | Check if an email is in any known breach via HIBP |
| `get_latest_breach` | Get the most recently added breach from HIBP |

---

## Data Sources

| Source | What it provides | Auth | Cost |
|--------|-----------------|------|------|
| [abuse.ch](https://abuse.ch/) (URLhaus, MalwareBazaar, ThreatFox, Feodo) | Malware URLs, hashes, C2s, botnet IPs | `ABUSECH_API_KEY` | Free |
| [AlienVault OTX](https://otx.alienvault.com/) | Community threat pulses, IOC enrichment | `OTX_API_KEY` | Free |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities catalog | None | Free |
| [Ahmia.fi](https://ahmia.fi/) | Dark web search (.onion index) | None | Free |
| [HIBP Passwords](https://haveibeenpwned.com/Passwords) | Breached password check (k-anonymity) | None | Free |
| [HIBP Email](https://haveibeenpwned.com/API/Key) | Email breach lookup | `HIBP_API_KEY` | $4.50/mo |
| [LeakCheck](https://leakcheck.io/) | Dark web breach data (7B+ records) | `LEAKCHECK_API_KEY` | $10/mo |

All optional keys degrade gracefully. The server runs fine without them and returns a clear error message when a tool needs a key that isn't configured.

---

## Architecture

```
Claude Code
    |
    | Streamable HTTP (port 3707, /mcp)
    v
mcp-threatintel (mcp_threatintel.server)
    |
    |-- SQLite cache (threatintel.db)  <-- populated by poller
    |-- Live API calls (LeakCheck, HIBP, Ahmia)
    v
threatintel-poller (mcp_threatintel.poller)
    |
    |-- abuse.ch feeds (URLhaus, MalwareBazaar, ThreatFox, Feodo)
    |-- AlienVault OTX pulses
    |-- CISA KEV catalog
    (syncs hourly by default)
```

The poller runs as a separate container and syncs threat feeds into a shared SQLite database. The MCP server reads from the cache for fast lookups, with live API calls only for on-demand services (LeakCheck, HIBP, Ahmia).

---

## Setup

### 1. Clone and configure

```bash
git clone https://github.com/pete-builds/mcp-threatintel.git
cd mcp-threatintel
cp .env.example .env
```

Edit `.env` and add your API keys. Of the feed keys, only `ABUSECH_API_KEY` is required. All others are optional.

Then generate the bearer token the server requires and put it in `.env` as `MCP_AUTH_TOKEN`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
chmod 600 .env
```

The server will not start over HTTP without it. See [Authentication](#authentication).

### 2. Start the stack

```bash
docker compose up -d
```

This starts two containers:
- `mcp-threatintel`: the MCP server on port 3707. Needs `MCP_AUTH_TOKEN`.
- `threatintel-poller`: background feed sync (runs every hour). Needs no token.

The poller will do an initial sync on first start. Give it a minute before the tools have data.

### 3. Connect to Claude Code

Register the MCP server with the Claude CLI, sending the token as a bearer header:

```bash
claude mcp add --transport http --scope user threatintel http://localhost:3707/mcp \
  --header "Authorization: Bearer <your token>"
```

Or add it to your MCP client configuration:

```json
{
  "mcpServers": {
    "threatintel": {
      "type": "http",
      "url": "http://localhost:3707/mcp",
      "headers": {
        "Authorization": "Bearer <your token>"
      }
    }
  }
}
```

Restart Claude Code. The 12 tools will show up as `mcp__threatintel__*`. A client that sends no header, or the wrong token, gets `401 Unauthorized` and no tools.

---

## Authentication

**A bearer token is required for the HTTP transport.** There is no unauthenticated mode: with no token the server exits at startup instead of listening.

| | |
|---|---|
| Variable | `MCP_AUTH_TOKEN` |
| Generate | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| Where it goes | `.env` on the host, mode 600 (`chmod 600 .env`). Never in `docker-compose.yml`, never in git. |
| What clients send | `Authorization: Bearer <token>` on every request to `/mcp` |

What to expect:

- **No token, or a blank one.** The server logs `Bearer token required for client 'threatintel' but not provided` and exits non-zero before it binds the port. Under `restart: unless-stopped` the container restarts in a loop until the token is set. `.env.example` ships `MCP_AUTH_TOKEN=` blank on purpose, so a copied example refuses to start rather than run with a token everyone knows.
- **`MCP_AUTH_REQUIRED=false` does not open the HTTP port.** The server then exits with `Refusing to start streamable-http with no auth provider`.
- **`MCP_THREATINTEL_AUTH_TOKEN`** is the older name for the same token. It is still accepted, and it wins when both names are set. Set one of them, not both. `MCP_AUTH_TOKEN` is the canonical name.
- **The container healthcheck needs no token.** It probes a path outside `/mcp` and stays healthy with auth on.
- **The poller needs no token.** It serves nothing and never reads the variable.
- **Rotating the token:** change it in `.env`, run `docker compose up -d` to recreate the server container, then update the header in every client.

### Upgrading from 0.3.0 or earlier

Earlier versions ran without a token unless you set one. Before you pull 0.4.0 or later, add `MCP_AUTH_TOKEN` to `.env` on the host and add the `Authorization` header to every client. If the token is missing when the new image starts, the server container will not come up.

### stdio for local development

stdio is a local pipe with no network surface, so it needs no token:

```bash
MCP_TRANSPORT=stdio DB_PATH=./threatintel.db mcp-threatintel
```

`MCP_TRANSPORT=stdio` is the only setting required. Without it the server defaults to HTTP and asks for the token.

---

## API Keys

```bash
# Required
ABUSECH_API_KEY   # Register free at https://auth.abuse.ch/

# Optional (free)
OTX_API_KEY       # Register free at https://otx.alienvault.com/

# Optional (paid)
HIBP_API_KEY      # $4.50/mo at https://haveibeenpwned.com/API/Key
LEAKCHECK_API_KEY # $10/mo at https://leakcheck.io/
```

---

## Notes

- `docker-compose.yml` uses `network_mode: host`. The MCP server binds to `0.0.0.0:3707`. If you're running this on a server (not just localhost), add a firewall rule to restrict access.
- A bearer token is required for HTTP. See [Authentication](#authentication). The token is one layer, not the only one: keep the firewall rule too.
- The SQLite database is stored in a named Docker volume (`threatintel-data`). It persists across container restarts.
- LeakCheck results redact most of the exposed password value. Only the first and last two characters are shown.
- HIBP password checks use k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the API. The full password never leaves the machine.

---

## Credits

Built by [Pete Stergion](https://github.com/pete-builds) for use with [Claude Code](https://claude.com/claude-code).

Related: [claude-research-agent](https://github.com/pete-builds/claude-research-agent) — the research skill that uses this server for security investigations.
