"""MCP ThreatIntel - Threat intelligence MCP server.

Provides Claude Code tools for IOC lookups, threat search, CVE checks,
OTX pulse search, and LeakCheck breach lookups via the Model Context
Protocol (Streamable HTTP transport).

Reads from a local SQLite cache populated by poller.py, with live API
fallback for LeakCheck (on-demand) and OTX (enrichment).
"""

import logging
import os

from dotenv import load_dotenv
from fastmcp import FastMCP
from pete_mcp_core import (
    build_auth_provider,
    configure_logging,
    format_response,
    run_server,
)
from pete_mcp_core.settings import BaseCoreSettings
from pydantic import AliasChoices, Field, SecretStr

from mcp_threatintel.clients.ahmia import AhmiaClient
from mcp_threatintel.clients.hibp import HibpClient
from mcp_threatintel.clients.leakcheck import LeakCheckClient
from mcp_threatintel.clients.otx import OtxClient
from mcp_threatintel.db import (
    connect,
    init_db,
    lookup_indicator,
    lookup_indicator_in_pulses,
    search_iocs_fts,
    search_pulses_fts,
    search_vulns_fts,
    get_recent_iocs,
    get_recent_summary,
    lookup_cve as db_lookup_cve,
    get_feed_status as db_get_feed_status,
    get_db_stats,
)

load_dotenv()


class ThreatIntelSettings(BaseCoreSettings):
    db_path: str = Field(
        default="/data/threatintel.db",
        validation_alias=AliasChoices("DB_PATH", "MCP_DB_PATH"),
        description="Path to the SQLite cache populated by the poller.",
    )
    hibp_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("HIBP_API_KEY", "MCP_HIBP_API_KEY")
    )
    leakcheck_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("LEAKCHECK_API_KEY", "MCP_LEAKCHECK_API_KEY"),
    )
    otx_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("OTX_API_KEY", "MCP_OTX_API_KEY")
    )
    # Preserve backward compat for the legacy MCP_THREATINTEL_AUTH_TOKEN name.
    threatintel_auth_token: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "MCP_THREATINTEL_AUTH_TOKEN", "MCP_AUTH_TOKEN"
        ),
    )


settings = ThreatIntelSettings()
configure_logging(settings.log_level, settings.log_format)
logger = logging.getLogger("threatintel.server")

if not os.path.exists(settings.db_path):
    logger.warning(
        "Database not found at %s. Poller may not have run yet.", settings.db_path
    )

# Create the schema once at startup, then close. Every tool call opens its own
# short-lived connection via db.connect() so no sqlite3 connection is shared
# across FastMCP's worker threads.
DB_PATH = settings.db_path  # module-level alias kept for backward compatibility
init_db(DB_PATH).close()


def _secret(v: SecretStr | None) -> str:
    return v.get_secret_value() if v else ""


# Optional clients (may not have API keys)
_leakcheck = LeakCheckClient(_secret(settings.leakcheck_api_key)) if settings.leakcheck_api_key else None
_otx = OtxClient(_secret(settings.otx_api_key)) if settings.otx_api_key else None
_hibp = HibpClient(api_key=_secret(settings.hibp_api_key))
_ahmia = AhmiaClient()

mcp = FastMCP(
    "ThreatIntel",
    auth=build_auth_provider(
        settings.threatintel_auth_token,
        client_id="threatintel",
        required=settings.auth_required,
        logger=logger,
    ),
)


# Alias so existing `_format(...)` call sites stay unchanged.
_format = format_response


# --- Tool annotations ---
# Twelve tools, all of them lookups, and not one writes anything a caller can
# observe. That is worth DECLARING rather than leaving to be inferred: an
# unannotated read-only server and an unannotated server full of delete tools
# are indistinguishable in the manifest, so a client trying to be careful has
# to be careful about everything, which in practice means being careful about
# nothing.
#
# The open-world split is real and is exactly half. Six tools query the local
# SQLite cache and never open a socket: lookup_ioc, search_threats,
# get_recent_threats, lookup_cve, get_feed_status, search_pulses. The other six
# call out to LeakCheck, Ahmia, or HIBP. Marking all twelve open-world would
# have been the easy uniform answer and would have been wrong about half the
# surface -- the cache is refreshed by a separate sync process, so the DATA
# originates externally, but these tools do not go and get it.
#
# Read-only is not the same as private, and these hints do not claim it is.
# check_password_breach sends the first five characters of a SHA-1 hash to
# HIBP, which is a k-anonymity property documented on the tool itself and not
# something an annotation can express. These hints describe EFFECTS on the
# world, and the effect of every tool here is none.

#: Reads only, over the network. Safe to repeat: an answer may differ between
#: two identical calls because an upstream feed changed, not because the call
#: changed it.
READ_REMOTE = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

#: Reads only, from the local cache. Never opens a socket.
READ_LOCAL = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def _clean_row(row: dict) -> dict:
    """Remove raw_json from results to keep responses concise."""
    return {k: v for k, v in row.items() if k != "raw_json"}


# ============================================================
# Threat intelligence tools
# ============================================================


@mcp.tool(annotations=READ_LOCAL)
async def lookup_ioc(indicator: str) -> str:
    """Check if an IP, domain, hash, or URL appears in any threat feed.

    Searches across all cached feeds (URLhaus, MalwareBazaar, ThreatFox,
    Feodo Tracker, AlienVault OTX). Returns all matches with source,
    confidence, tags, malware family, and threat type.

    Args:
        indicator: The IOC to look up. Can be an IP address, domain name,
            file hash (MD5/SHA1/SHA256), or URL.

    Returns:
        JSON with all matches grouped by source. Empty matches if clean.
    """
    with connect(DB_PATH) as conn:
        matches = lookup_indicator(conn, indicator)
        pulse_matches = lookup_indicator_in_pulses(conn, indicator)

    return _format({
        "indicator": indicator,
        "match_count": len(matches),
        "matches": [_clean_row(m) for m in matches],
        "otx_pulse_count": len(pulse_matches),
        "otx_pulses": [_clean_row(p) for p in pulse_matches],
    })


@mcp.tool(annotations=READ_LOCAL)
async def search_threats(
    query: str,
    source: str = "",
    days: int = 30,
) -> str:
    """Full-text search across all threat intelligence data.

    Searches IOCs, OTX pulses, and CISA vulnerabilities by keyword.
    Useful for "anything related to Emotet?" or "what do we know about Log4j?"

    Args:
        query: Search keywords (e.g. "emotet", "log4j", "ransomware").
        source: Filter to a specific source: urlhaus, malwarebazaar,
            threatfox, feodo, otx, cisa. Leave empty for all sources.
        days: Only return results from the last N days (default: 30).

    Returns:
        JSON with matching IOCs, pulses, and vulnerabilities.
    """
    with connect(DB_PATH) as conn:
        iocs = search_iocs_fts(conn, query, source=source, days=days)
        pulses = search_pulses_fts(conn, query)
        vulns = search_vulns_fts(conn, query)

    return _format({
        "query": query,
        "ioc_count": len(iocs),
        "iocs": [_clean_row(i) for i in iocs],
        "pulse_count": len(pulses),
        "pulses": [_clean_row(p) for p in pulses],
        "vuln_count": len(vulns),
        "vulnerabilities": [_clean_row(v) for v in vulns],
    })


@mcp.tool(annotations=READ_LOCAL)
async def get_recent_threats(
    source: str = "",
    hours: int = 24,
) -> str:
    """Get the most recent threat intelligence from the last N hours.

    Great for "what's hot right now" or daily threat briefings.

    Args:
        source: Filter to one source, or leave empty for all.
        hours: How far back to look (default: 24, max: 168).

    Returns:
        JSON with recent IOCs and summary stats.
    """
    hours = min(hours, 168)
    with connect(DB_PATH) as conn:
        iocs = get_recent_iocs(conn, source=source, hours=hours)
        summary = get_recent_summary(conn, hours=hours)

    return _format({
        "hours": hours,
        "source_filter": source or "all",
        "summary": summary,
        "ioc_count": len(iocs),
        "iocs": [_clean_row(i) for i in iocs],
    })


@mcp.tool(annotations=READ_LOCAL)
async def lookup_cve(cve_id: str) -> str:
    """Look up a CVE in the CISA Known Exploited Vulnerabilities catalog.

    Args:
        cve_id: The CVE identifier (e.g. "CVE-2024-1234").

    Returns:
        JSON with vulnerability details including vendor, product,
        description, remediation due date, and ransomware usage.
    """
    with connect(DB_PATH) as conn:
        vuln = db_lookup_cve(conn, cve_id)
    if vuln:
        return _format({"found": True, **_clean_row(vuln)})
    return _format({"found": False, "cve_id": cve_id, "message": "Not found in CISA KEV catalog"})


@mcp.tool(annotations=READ_LOCAL)
async def get_feed_status() -> str:
    """Show sync status for all threat intelligence feeds.

    Returns last sync time, record counts, and error status for each
    data source. Use this to check if feeds are healthy and current.

    Returns:
        JSON with per-source sync status and overall database stats.
    """
    with connect(DB_PATH) as conn:
        feeds = db_get_feed_status(conn)
        stats = get_db_stats(conn)

    return _format({
        "database_stats": stats,
        "feeds": feeds,
        "leakcheck_available": _leakcheck is not None,
        "otx_live_available": _otx is not None,
        "hibp_key_configured": _hibp._has_key,
        "ahmia_available": True,
    })


@mcp.tool(annotations=READ_LOCAL)
async def search_pulses(
    query: str,
    tags: str = "",
) -> str:
    """Search AlienVault OTX community threat pulses.

    OTX pulses are community-contributed threat reports with IOCs,
    MITRE ATT&CK mappings, and references.

    Args:
        query: Search keywords (e.g. "APT29", "phishing campaign").
        tags: Comma-separated tags to filter by (e.g. "ransomware,apt").

    Returns:
        JSON with matching pulses including name, author, description,
        and MITRE ATT&CK IDs.
    """
    with connect(DB_PATH) as conn:
        pulses = search_pulses_fts(conn, query, tags=tags)

    return _format({
        "query": query,
        "tags_filter": tags or "none",
        "count": len(pulses),
        "pulses": [_clean_row(p) for p in pulses],
    })


@mcp.tool(annotations=READ_REMOTE)
async def check_breach(
    query: str,
    query_type: str = "auto",
) -> str:
    """Check LeakCheck for breached credentials from dark web dumps.

    Searches 7B+ records from breach dumps, paste sites, and dark web
    markets. Use this to check if an email, domain, username, or hash
    has been compromised.

    Args:
        query: The value to search (email, domain, username, hash, phone).
        query_type: Type of query: auto, email, domain, username, hash,
            phone. Default: auto (LeakCheck detects type).

    Returns:
        JSON with breach records including source, date, and exposed data.
    """
    if not _leakcheck:
        return _format({
            "error": "LeakCheck not configured. Set LEAKCHECK_API_KEY in .env.",
        })

    data = await _leakcheck.lookup(query, query_type=query_type)
    return _format(data)


@mcp.tool(annotations=READ_REMOTE)
async def check_domain_breaches(domain: str) -> str:
    """Check all known breaches for a domain.

    Answers "Has anyone at litellm.ai been compromised?" Returns
    affected accounts and breach sources from dark web data.

    Args:
        domain: Domain to check (e.g. "litellm.ai").

    Returns:
        JSON with affected accounts, breach sources, and dates.
    """
    if not _leakcheck:
        return _format({
            "error": "LeakCheck not configured. Set LEAKCHECK_API_KEY in .env.",
        })

    data = await _leakcheck.lookup_domain(domain)
    return _format(data)


# ============================================================
# Dark web search (Ahmia)
# ============================================================


@mcp.tool(annotations=READ_REMOTE)
async def search_darkweb(query: str, max_results: int = 20) -> str:
    """Search the dark web via Ahmia.fi (.onion site index).

    Searches Ahmia's index of Tor hidden services. Results include
    .onion URLs, titles, and descriptions. You cannot visit these
    URLs without Tor, but the metadata is valuable for research.

    Args:
        query: Search terms (e.g. "TeamPCP", "litellm credentials").
        max_results: Maximum results to return (default: 20).

    Returns:
        JSON with dark web search results including .onion URLs.
    """
    data = await _ahmia.search(query, max_results=max_results)
    return _format(data)


# ============================================================
# Have I Been Pwned
# ============================================================


@mcp.tool(annotations=READ_REMOTE)
async def check_password_breach(password: str) -> str:
    """Check if a password has been exposed in any known data breach.

    Uses HIBP's k-anonymity model. Only the first 5 characters of the
    SHA-1 hash are sent to the API. The full password never leaves
    this machine. Free, no API key needed.

    Args:
        password: The password to check.

    Returns:
        JSON with whether the password was found and how many times.
    """
    data = await _hibp.check_password(password)
    return _format(data)


@mcp.tool(annotations=READ_REMOTE)
async def check_email_breaches(email: str) -> str:
    """Check if an email has been in any known data breaches via HIBP.

    Requires HIBP API key ($4.50/mo). Without a key, falls back to
    returning the breach catalog so you can search manually.

    Args:
        email: Email address to check.

    Returns:
        JSON with breaches containing this email, or error if no key.
    """
    data = await _hibp.check_email(email)
    return _format(data)


@mcp.tool(annotations=READ_REMOTE)
async def get_latest_breach() -> str:
    """Get the most recently added breach from Have I Been Pwned.

    Free, no API key needed. Useful for staying current on new breaches.

    Returns:
        JSON with the latest breach details (name, date, data classes, count).
    """
    data = await _hibp.get_latest_breach()
    return _format(data)


# ============================================================
# Entry point
# ============================================================

def main() -> None:
    run_server(mcp, default_port=3707, default_transport="streamable-http")


if __name__ == "__main__":
    main()
