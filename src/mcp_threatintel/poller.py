"""Threat intelligence feed poller.

Runs in a loop (default: hourly), pulling delta data from each feed
and upserting into the SQLite cache. Each source polls independently
so one failure doesn't block others.

Usage:
    python poller.py                    # Run once
    python poller.py --loop             # Run in loop (default: 3600s interval)
    python poller.py --loop --interval 1800  # Custom interval
"""

import argparse
import asyncio
import logging
import os
import time

from dotenv import load_dotenv

from mcp_threatintel.clients.abusech import URLhausClient, MalwareBazaarClient, ThreatFoxClient, FeodoClient
from mcp_threatintel.clients.otx import OtxClient
from mcp_threatintel.clients.cisa import CisaClient
from mcp_threatintel.db import init_db, upsert_ioc, upsert_pulse, upsert_pulse_indicator, upsert_vulnerability, update_feed_sync, rebuild_fts

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("threatintel.poller")

DB_PATH = os.getenv("DB_PATH", "/data/threatintel.db")
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")


async def poll_urlhaus(conn):
    """Poll URLhaus for recent malicious URLs."""
    try:
        client = URLhausClient(api_key=ABUSECH_API_KEY)
        iocs = await client.get_recent(limit=1000)
        added = 0
        for ioc in iocs:
            upsert_ioc(conn, **ioc)
            added += 1
        conn.commit()
        update_feed_sync(conn, "urlhaus", added)
        logger.info("urlhaus: upserted %d IOCs", added)
        await client.close()
    except Exception as e:
        logger.error("urlhaus poll failed: %s", e)
        update_feed_sync(conn, "urlhaus", 0, status="error", error=str(e))


async def poll_malwarebazaar(conn):
    """Poll MalwareBazaar for recent malware samples."""
    try:
        client = MalwareBazaarClient(api_key=ABUSECH_API_KEY)
        iocs = await client.get_recent(limit=100)
        added = 0
        for ioc in iocs:
            upsert_ioc(conn, **ioc)
            added += 1
        conn.commit()
        update_feed_sync(conn, "malwarebazaar", added)
        logger.info("malwarebazaar: upserted %d IOCs", added)
        await client.close()
    except Exception as e:
        logger.error("malwarebazaar poll failed: %s", e)
        update_feed_sync(conn, "malwarebazaar", 0, status="error", error=str(e))


async def poll_threatfox(conn):
    """Poll ThreatFox for recent IOCs."""
    try:
        client = ThreatFoxClient(api_key=ABUSECH_API_KEY)
        iocs = await client.get_recent(days=1)
        added = 0
        for ioc in iocs:
            upsert_ioc(conn, **ioc)
            added += 1
        conn.commit()
        update_feed_sync(conn, "threatfox", added)
        logger.info("threatfox: upserted %d IOCs", added)
        await client.close()
    except Exception as e:
        logger.error("threatfox poll failed: %s", e)
        update_feed_sync(conn, "threatfox", 0, status="error", error=str(e))


async def poll_feodo(conn):
    """Poll Feodo Tracker for C2 blocklist."""
    try:
        client = FeodoClient()
        iocs = await client.get_blocklist()
        added = 0
        for ioc in iocs:
            upsert_ioc(conn, **ioc)
            added += 1
        conn.commit()
        update_feed_sync(conn, "feodo", added)
        logger.info("feodo: upserted %d IOCs", added)
        await client.close()
    except Exception as e:
        logger.error("feodo poll failed: %s", e)
        update_feed_sync(conn, "feodo", 0, status="error", error=str(e))


async def poll_otx(conn):
    """Poll AlienVault OTX for subscribed pulses."""
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        logger.warning("otx: OTX_API_KEY not set, skipping")
        update_feed_sync(conn, "otx", 0, status="error", error="OTX_API_KEY not set")
        return

    try:
        client = OtxClient(api_key)

        # Get last sync time for delta
        row = conn.execute("SELECT last_sync FROM feed_sync WHERE source = 'otx'").fetchone()
        modified_since = row["last_sync"] if row else ""

        pulses = await client.get_subscribed_pulses(modified_since=modified_since)
        added = 0
        for p in pulses:
            shaped = client.shape_pulse(p)
            upsert_pulse(conn, shaped)
            # Extract and store indicators
            indicators = p.get("indicators", [])
            for pulse_id, indicator, ioc_type in client.shape_indicators(p["id"], indicators):
                upsert_pulse_indicator(conn, pulse_id, indicator, ioc_type)
            added += 1
        conn.commit()
        update_feed_sync(conn, "otx", added)
        logger.info("otx: upserted %d pulses", added)
        await client.close()
    except Exception as e:
        logger.error("otx poll failed: %s", e)
        update_feed_sync(conn, "otx", 0, status="error", error=str(e))


async def poll_cisa_kev(conn):
    """Poll CISA KEV catalog."""
    try:
        client = CisaClient()
        vulns = await client.get_kev_catalog()
        added = 0
        for v in vulns:
            upsert_vulnerability(conn, v)
            added += 1
        conn.commit()
        update_feed_sync(conn, "cisa_kev", added)
        logger.info("cisa_kev: upserted %d vulnerabilities", added)
        await client.close()
    except Exception as e:
        logger.error("cisa_kev poll failed: %s", e)
        update_feed_sync(conn, "cisa_kev", 0, status="error", error=str(e))


async def poll_all():
    """Run all feed polls."""
    conn = init_db(DB_PATH)
    logger.info("=== Starting poll cycle ===")
    start = time.monotonic()

    # Poll all feeds (sequentially to be kind to rate limits)
    await poll_urlhaus(conn)
    await poll_malwarebazaar(conn)
    await poll_threatfox(conn)
    await poll_feodo(conn)
    await poll_otx(conn)
    await poll_cisa_kev(conn)

    # Rebuild FTS indexes
    try:
        rebuild_fts(conn)
        logger.info("FTS indexes rebuilt")
    except Exception as e:
        logger.error("FTS rebuild failed: %s", e)

    elapsed = time.monotonic() - start
    logger.info("=== Poll cycle complete in %.1fs ===", elapsed)
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Threat intel feed poller")
    parser.add_argument("--loop", action="store_true", help="Run in continuous loop")
    parser.add_argument("--interval", type=int, default=3600, help="Loop interval in seconds (default: 3600)")
    args = parser.parse_args()

    if args.loop:
        logger.info("Starting poller loop (interval: %ds)", args.interval)
        while True:
            asyncio.run(poll_all())
            logger.info("Sleeping %ds until next poll...", args.interval)
            time.sleep(args.interval)
    else:
        asyncio.run(poll_all())


if __name__ == "__main__":
    main()
