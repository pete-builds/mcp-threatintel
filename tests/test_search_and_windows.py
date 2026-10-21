"""Regression tests: FTS5 query safety and time-window filtering.

1. search_threats / search_pulses handed raw text to FTS5 MATCH, so CVE ids,
   IPs, domains, quotes and questions raised OperationalError.
2. ThreatFox rows were stored with NULL timestamps (the client read keys the
   API does not send) and every feed's timestamps were stored verbatim, so the
   time-window filters compared "2026-09-06 23:30:00" against
   "2026-09-06T23:00:00+00:00" as strings and dropped rows inside the window.
"""

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_threatintel import db, server  # noqa: E402
from mcp_threatintel.clients.abusech import ThreatFoxClient  # noqa: E402

AWKWARD_QUERIES = [
    "CVE-2026-109618",
    "Calif.io",
    "1.2.3.4",
    "evil.com:443",
    "host:8080",
    'emotet"',
    '"',
    "what do we know about Log4j?",
    "-",
    "*",
    "",
    "   ",
]


@pytest.fixture()
def conn(tmp_path):
    c = db.init_db(str(tmp_path / "t.db"))
    yield c
    c.close()


def _feed_ts(dt: datetime) -> str:
    """The ThreatFox / abuse.ch timestamp shape: '2020-12-08 13:36:27 UTC'."""
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _threatfox_record(ioc: str, first_seen: str, last_seen=None) -> dict:
    """One get_iocs record in the shape the ThreatFox API documents."""
    return {
        "id": "41",
        "ioc": ioc,
        "threat_type": "botnet_cc",
        "ioc_type": "domain",
        "malware": "win.asyncrat",
        "malware_printable": "AsyncRAT",
        "confidence_level": 50,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "reporter": "abuse_ch",
        "tags": ["asyncrat"],
    }


def _ingest_threatfox(conn, records):
    client = ThreatFoxClient("")

    async def fake_post(path, data=None, json_data=None):
        return {"query_status": "ok", "data": records}

    client.post = fake_post
    rows = asyncio.run(client.get_recent(days=1))
    for r in rows:
        db.upsert_ioc(conn, **r)
    conn.commit()
    db.rebuild_fts(conn)


# --- FTS5 query safety -------------------------------------------------------


@pytest.mark.parametrize("query", AWKWARD_QUERIES)
def test_fts_helpers_accept_awkward_input(conn, query):
    db.search_iocs_fts(conn, query)
    db.search_iocs_fts(conn, query, source="threatfox", days=3650)
    db.search_pulses_fts(conn, query)
    db.search_vulns_fts(conn, query)


def test_fts_query_quotes_every_token():
    assert db.fts_query("CVE-2026-109618") == '"CVE-2026-109618"'
    assert db.fts_query('a"b  c') == '"a""b" "c"'
    assert db.fts_query("   ") == ""


def test_fts_finds_cve_ip_and_domain(conn):
    now = datetime.now(timezone.utc).isoformat()
    for ind, typ in (("1.2.3.4", "ip"), ("calif.io", "domain")):
        db.upsert_ioc(
            conn, indicator=ind, type=typ, source="urlhaus", first_seen=now,
            last_seen=now, tags="", confidence=None, malware_family="",
            threat_type="", raw_json="{}",
        )
    db.upsert_vulnerability(conn, {
        "cve_id": "CVE-2026-109618", "vendor": "Acme", "product": "Widget",
        "vulnerability_name": "Acme Widget RCE", "description": "test",
        "date_added": "2026-10-01", "due_date": "2026-10-22",
        "known_ransomware": "Unknown", "notes": "", "raw_json": "{}",
    })
    conn.commit()
    db.rebuild_fts(conn)
    assert [r["indicator"] for r in db.search_iocs_fts(conn, "1.2.3.4")] == ["1.2.3.4"]
    assert [r["indicator"] for r in db.search_iocs_fts(conn, "Calif.io")] == ["calif.io"]
    assert [r["cve_id"] for r in db.search_vulns_fts(conn, "CVE-2026-109618")] == ["CVE-2026-109618"]


@pytest.mark.parametrize("query", ["CVE-2026-109618", "Calif.io", 'emotet"', "what is Log4j?"])
def test_search_tools_return_json_for_awkward_queries(query):
    threats = getattr(server.search_threats, "fn", server.search_threats)
    assert json.loads(asyncio.run(threats(query=query)))["query"] == query
    pulses = getattr(server.search_pulses, "fn", server.search_pulses)
    assert json.loads(asyncio.run(pulses(query=query)))["query"] == query


# --- Time windows ------------------------------------------------------------


def test_threatfox_record_lands_inside_window(conn):
    now = datetime.now(timezone.utc)
    _ingest_threatfox(conn, [_threatfox_record("recent.example", _feed_ts(now - timedelta(minutes=30)))])

    recent = db.get_recent_iocs(conn, source="threatfox", hours=1)
    assert [r["indicator"] for r in recent] == ["recent.example"]
    found = db.search_iocs_fts(conn, "AsyncRAT", source="threatfox", days=1)
    assert [r["indicator"] for r in found] == ["recent.example"]
    assert db.get_recent_summary(conn, hours=1)["threatfox"]["count"] == 1


def test_threatfox_record_excluded_outside_window(conn):
    now = datetime.now(timezone.utc)
    _ingest_threatfox(conn, [_threatfox_record("old.example", _feed_ts(now - timedelta(days=10)))])

    assert db.get_recent_iocs(conn, source="threatfox", hours=24) == []
    assert db.search_iocs_fts(conn, "AsyncRAT", source="threatfox", days=1) == []
    found = db.search_iocs_fts(conn, "AsyncRAT", source="threatfox", days=30)
    assert [r["indicator"] for r in found] == ["old.example"]


def test_normalize_ts_feed_shapes():
    want = "2026-09-06T23:30:00+00:00"
    assert db.normalize_ts("2026-09-06 23:30:00 UTC") == want
    assert db.normalize_ts("2026-09-06 23:30:00") == want
    assert db.normalize_ts("2026-09-06T23:30:00Z") == want
    assert db.normalize_ts("2026-09-07T01:30:00+02:00") == want
    assert db.normalize_ts("2026-09-06") == "2026-09-06T00:00:00+00:00"
    assert db.normalize_ts(None) is None
    assert db.normalize_ts("  ") is None


def test_migration_repairs_rows_written_by_older_builds(tmp_path):
    path = str(tmp_path / "old.db")
    c = db.init_db(path)
    ts = (datetime.now(timezone.utc) - timedelta(minutes=30)).replace(microsecond=0)
    raw_tf = str(_threatfox_record("legacy.example", _feed_ts(ts)))
    c.executemany(
        "INSERT INTO iocs (indicator, type, source, first_seen, last_seen, raw_json) VALUES (?,?,?,?,?,?)",
        [
            # Old ThreatFox rows: both columns NULL, timestamp only in raw_json.
            ("legacy.example", "domain", "threatfox", None, None, raw_tf),
            # Verbatim abuse.ch format.
            ("http://legacy.example/x", "url", "urlhaus", _feed_ts(ts), _feed_ts(ts), "{}"),
            # MalwareBazaar: last_seen null for samples seen once.
            ("a" * 64, "hash_sha256", "malwarebazaar", ts.strftime("%Y-%m-%d %H:%M:%S"), None, "{}"),
        ],
    )
    c.commit()
    c.close()

    c = db.init_db(path)  # startup runs the migration
    rows = c.execute("SELECT source, first_seen, last_seen FROM iocs ORDER BY source").fetchall()
    canonical = ts.isoformat()
    assert [tuple(r) for r in rows] == [
        ("malwarebazaar", canonical, canonical),
        ("threatfox", canonical, canonical),
        ("urlhaus", canonical, canonical),
    ]
    assert len(db.get_recent_iocs(c, hours=1)) == 3
    assert db.migrate_ioc_timestamps(c) == 0  # idempotent
    c.close()
