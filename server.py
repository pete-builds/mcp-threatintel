"""MCP ThreatIntel - Threat intelligence MCP server.

Provides Claude Code tools for IOC lookups, threat search, CVE checks,
OTX pulse search, and LeakCheck breach lookups via the Model Context
Protocol (Streamable HTTP transport).

Reads from a local SQLite cache populated by poller.py, with live API
fallback for LeakCheck (on-demand) and OTX (enrichment).
"""

import json
import logging
import os
import sys

from dotenv import load_dotenv
from fastmcp import FastMCP

from clients.ahmia import AhmiaClient
from clients.hibp import HibpClient
from clients.leakcheck import LeakCheckClient
from clients.otx import OtxClient
from db import (
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

DB_PATH = os.getenv("DB_PATH", "/data/threatintel.db")

if not os.path.exists(DB_PATH):
    print(f"WARNING: Database not found at {DB_PATH}. Poller may not have run yet.", file=sys.stderr)

conn = init_db(DB_PATH)

# Optional clients (may not have API keys)
_leakcheck = None
_otx = None
_hibp = HibpClient(api_key=os.getenv("HIBP_API_KEY", ""))
_ahmia = AhmiaClient()

if os.getenv("LEAKCHECK_API_KEY"):
    _leakcheck = LeakCheckClient(os.getenv("LEAKCHECK_API_KEY"))

if os.getenv("OTX_API_KEY"):
    _otx = OtxClient(os.getenv("OTX_API_KEY"))

mcp = FastMCP("ThreatIntel")


def _format(data: object) -> str:
    return json.dumps(data, indent=2, default=str)


def _clean_row(row: dict) -> dict:
    """Remove raw_json from results to keep responses concise."""
    return {k: v for k, v in row.items() if k != "raw_json"}


# ============================================================
# Threat intelligence tools
# ============================================================


@mcp.tool()
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
    matches = lookup_indicator(conn, indicator)
    pulse_matches = lookup_indicator_in_pulses(conn, indicator)

    return _format({
        "indicator": indicator,
        "match_count": len(matches),
        "matches": [_clean_row(m) for m in matches],
        "otx_pulse_count": len(pulse_matches),
        "otx_pulses": [_clean_row(p) for p in pulse_matches],
    })


@mcp.tool()
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


@mcp.tool()
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
    iocs = get_recent_iocs(conn, source=source, hours=hours)
    summary = get_recent_summary(conn, hours=hours)

    return _format({
        "hours": hours,
        "source_filter": source or "all",
        "summary": summary,
        "ioc_count": len(iocs),
        "iocs": [_clean_row(i) for i in iocs],
    })


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Look up a CVE in the CISA Known Exploited Vulnerabilities catalog.

    Args:
        cve_id: The CVE identifier (e.g. "CVE-2024-1234").

    Returns:
        JSON with vulnerability details including vendor, product,
        description, remediation due date, and ransomware usage.
    """
    vuln = db_lookup_cve(conn, cve_id)
    if vuln:
        return _format({"found": True, **_clean_row(vuln)})
    return _format({"found": False, "cve_id": cve_id, "message": "Not found in CISA KEV catalog"})


@mcp.tool()
async def get_feed_status() -> str:
    """Show sync status for all threat intelligence feeds.

    Returns last sync time, record counts, and error status for each
    data source. Use this to check if feeds are healthy and current.

    Returns:
        JSON with per-source sync status and overall database stats.
    """
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


@mcp.tool()
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
    pulses = search_pulses_fts(conn, query, tags=tags)

    return _format({
        "query": query,
        "tags_filter": tags or "none",
        "count": len(pulses),
        "pulses": [_clean_row(p) for p in pulses],
    })


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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


@mcp.tool()
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

if __name__ == "__main__":
    host = os.getenv("FASTMCP_HOST", os.getenv("MCP_HOST", "0.0.0.0"))
    port = os.getenv("FASTMCP_PORT", os.getenv("MCP_PORT", "3707"))
    # FastMCP 3.1.0 reads FASTMCP_HOST/FASTMCP_PORT env vars
    os.environ["FASTMCP_HOST"] = host
    os.environ["FASTMCP_PORT"] = str(port)
    print(f"Starting MCP ThreatIntel on {host}:{port} (Streamable HTTP transport)")
    mcp.run(transport="streamable-http")
