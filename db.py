"""SQLite database layer for threat intelligence cache.

Handles schema initialization, WAL mode, and provides upsert/query helpers
for IOCs, OTX pulses, CISA vulnerabilities, and feed sync tracking.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone


def init_db(path: str) -> sqlite3.Connection:
    """Initialize the database with schema and WAL mode."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    tags TEXT,
    confidence INTEGER,
    malware_family TEXT,
    threat_type TEXT,
    raw_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(indicator, source)
);

CREATE INDEX IF NOT EXISTS idx_iocs_indicator ON iocs(indicator);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);
CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen);

CREATE VIRTUAL TABLE IF NOT EXISTS iocs_fts USING fts5(
    indicator, tags, malware_family, threat_type,
    content=iocs, content_rowid=id
);

CREATE TABLE IF NOT EXISTS pulses (
    pulse_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    author TEXT,
    created TEXT,
    modified TEXT,
    tags TEXT,
    tlp TEXT,
    references_list TEXT,
    adversary TEXT,
    targeted_countries TEXT,
    malware_families TEXT,
    attack_ids TEXT,
    raw_json TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE VIRTUAL TABLE IF NOT EXISTS pulses_fts USING fts5(
    name, description, tags, adversary, malware_families,
    content=pulses, content_rowid=rowid
);

CREATE TABLE IF NOT EXISTS pulse_indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pulse_id TEXT NOT NULL REFERENCES pulses(pulse_id),
    indicator TEXT NOT NULL,
    type TEXT NOT NULL,
    UNIQUE(pulse_id, indicator)
);

CREATE INDEX IF NOT EXISTS idx_pulse_ind_indicator ON pulse_indicators(indicator);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT,
    product TEXT,
    vulnerability_name TEXT,
    description TEXT,
    date_added TEXT,
    due_date TEXT,
    known_ransomware TEXT,
    notes TEXT,
    raw_json TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE VIRTUAL TABLE IF NOT EXISTS vulns_fts USING fts5(
    cve_id, vendor, product, vulnerability_name, description,
    content=vulnerabilities, content_rowid=rowid
);

CREATE TABLE IF NOT EXISTS feed_sync (
    source TEXT PRIMARY KEY,
    last_sync TEXT NOT NULL,
    records_added INTEGER DEFAULT 0,
    records_total INTEGER DEFAULT 0,
    status TEXT DEFAULT 'ok',
    error_message TEXT
);
"""


# --- Upsert helpers (used by poller) ---


def upsert_ioc(conn: sqlite3.Connection, **kwargs) -> bool:
    """Insert or update an IOC. Returns True if a new row was inserted."""
    conn.execute(
        """INSERT INTO iocs (indicator, type, source, first_seen, last_seen,
           tags, confidence, malware_family, threat_type, raw_json)
           VALUES (:indicator, :type, :source, :first_seen, :last_seen,
           :tags, :confidence, :malware_family, :threat_type, :raw_json)
           ON CONFLICT(indicator, source) DO UPDATE SET
             last_seen = COALESCE(:last_seen, last_seen),
             tags = COALESCE(:tags, tags),
             confidence = COALESCE(:confidence, confidence),
             raw_json = :raw_json
        """,
        kwargs,
    )
    return conn.total_changes > 0


def upsert_pulse(conn: sqlite3.Connection, pulse: dict) -> None:
    """Insert or update an OTX pulse."""
    conn.execute(
        """INSERT INTO pulses (pulse_id, name, description, author, created,
           modified, tags, tlp, references_list, adversary, targeted_countries,
           malware_families, attack_ids, raw_json)
           VALUES (:pulse_id, :name, :description, :author, :created,
           :modified, :tags, :tlp, :references_list, :adversary,
           :targeted_countries, :malware_families, :attack_ids, :raw_json)
           ON CONFLICT(pulse_id) DO UPDATE SET
             modified = :modified,
             tags = :tags,
             raw_json = :raw_json
        """,
        pulse,
    )


def upsert_pulse_indicator(conn: sqlite3.Connection, pulse_id: str, indicator: str, ioc_type: str) -> None:
    """Insert a pulse indicator (ignore duplicates)."""
    conn.execute(
        "INSERT OR IGNORE INTO pulse_indicators (pulse_id, indicator, type) VALUES (?, ?, ?)",
        (pulse_id, indicator, ioc_type),
    )


def upsert_vulnerability(conn: sqlite3.Connection, vuln: dict) -> None:
    """Insert or update a CISA KEV vulnerability."""
    conn.execute(
        """INSERT INTO vulnerabilities (cve_id, vendor, product, vulnerability_name,
           description, date_added, due_date, known_ransomware, notes, raw_json)
           VALUES (:cve_id, :vendor, :product, :vulnerability_name,
           :description, :date_added, :due_date, :known_ransomware, :notes, :raw_json)
           ON CONFLICT(cve_id) DO UPDATE SET
             description = :description,
             raw_json = :raw_json
        """,
        vuln,
    )


def update_feed_sync(conn: sqlite3.Connection, source: str, records_added: int, status: str = "ok", error: str = None) -> None:
    """Update the sync status for a feed source."""
    total = conn.execute("SELECT COUNT(*) FROM iocs WHERE source = ?", (source,)).fetchone()[0]
    conn.execute(
        """INSERT INTO feed_sync (source, last_sync, records_added, records_total, status, error_message)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(source) DO UPDATE SET
             last_sync = ?, records_added = ?, records_total = ?, status = ?, error_message = ?
        """,
        (source, _now(), records_added, total, status, error,
         _now(), records_added, total, status, error),
    )
    conn.commit()


def rebuild_fts(conn: sqlite3.Connection) -> None:
    """Rebuild all FTS5 indexes after bulk inserts."""
    conn.execute("INSERT INTO iocs_fts(iocs_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO pulses_fts(pulses_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO vulns_fts(vulns_fts) VALUES('rebuild')")
    conn.commit()


# --- Query helpers (used by MCP server) ---


def lookup_indicator(conn: sqlite3.Connection, indicator: str) -> list[dict]:
    """Look up an indicator across all sources."""
    rows = conn.execute(
        "SELECT * FROM iocs WHERE indicator = ?", (indicator,)
    ).fetchall()
    return [dict(r) for r in rows]


def lookup_indicator_in_pulses(conn: sqlite3.Connection, indicator: str) -> list[dict]:
    """Find OTX pulses containing a specific indicator."""
    rows = conn.execute(
        """SELECT p.pulse_id, p.name, p.author, p.created, p.tags, p.tlp, p.adversary
           FROM pulse_indicators pi
           JOIN pulses p ON pi.pulse_id = p.pulse_id
           WHERE pi.indicator = ?
        """,
        (indicator,),
    ).fetchall()
    return [dict(r) for r in rows]


def search_iocs_fts(conn: sqlite3.Connection, query: str, source: str = "", days: int = 30) -> list[dict]:
    """Full-text search across IOCs."""
    cutoff = _days_ago(days)
    if source:
        rows = conn.execute(
            """SELECT i.* FROM iocs i
               JOIN iocs_fts f ON i.id = f.rowid
               WHERE iocs_fts MATCH ? AND i.source = ? AND i.last_seen >= ?
               ORDER BY rank LIMIT 50
            """,
            (query, source, cutoff),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT i.* FROM iocs i
               JOIN iocs_fts f ON i.id = f.rowid
               WHERE iocs_fts MATCH ? AND i.last_seen >= ?
               ORDER BY rank LIMIT 50
            """,
            (query, cutoff),
        ).fetchall()
    return [dict(r) for r in rows]


def search_pulses_fts(conn: sqlite3.Connection, query: str, tags: str = "") -> list[dict]:
    """Full-text search across OTX pulses."""
    rows = conn.execute(
        """SELECT p.* FROM pulses p
           JOIN pulses_fts f ON p.rowid = f.rowid
           WHERE pulses_fts MATCH ?
           ORDER BY rank LIMIT 30
        """,
        (query,),
    ).fetchall()
    results = [dict(r) for r in rows]
    if tags:
        tag_list = [t.strip().lower() for t in tags.split(",")]
        results = [
            r for r in results
            if any(t in (r.get("tags") or "").lower() for t in tag_list)
        ]
    return results


def search_vulns_fts(conn: sqlite3.Connection, query: str) -> list[dict]:
    """Full-text search across CISA KEV vulnerabilities."""
    rows = conn.execute(
        """SELECT v.* FROM vulnerabilities v
           JOIN vulns_fts f ON v.rowid = f.rowid
           WHERE vulns_fts MATCH ?
           ORDER BY rank LIMIT 30
        """,
        (query,),
    ).fetchall()
    return [dict(r) for r in rows]


def get_recent_iocs(conn: sqlite3.Connection, source: str = "", hours: int = 24) -> list[dict]:
    """Get IOCs from the last N hours."""
    cutoff = _hours_ago(hours)
    if source:
        rows = conn.execute(
            "SELECT * FROM iocs WHERE source = ? AND last_seen >= ? ORDER BY last_seen DESC LIMIT 100",
            (source, cutoff),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM iocs WHERE last_seen >= ? ORDER BY last_seen DESC LIMIT 100",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_recent_summary(conn: sqlite3.Connection, hours: int = 24) -> dict:
    """Get summary stats for recent IOCs."""
    cutoff = _hours_ago(hours)
    rows = conn.execute(
        """SELECT source, COUNT(*) as count,
           GROUP_CONCAT(DISTINCT malware_family) as families
           FROM iocs WHERE last_seen >= ?
           GROUP BY source
        """,
        (cutoff,),
    ).fetchall()
    return {r["source"]: {"count": r["count"], "families": r["families"]} for r in rows}


def lookup_cve(conn: sqlite3.Connection, cve_id: str) -> dict | None:
    """Look up a CVE in the CISA KEV catalog."""
    row = conn.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id.upper(),)).fetchone()
    return dict(row) if row else None


def get_feed_status(conn: sqlite3.Connection) -> list[dict]:
    """Get sync status for all feeds."""
    rows = conn.execute("SELECT * FROM feed_sync ORDER BY source").fetchall()
    return [dict(r) for r in rows]


def get_db_stats(conn: sqlite3.Connection) -> dict:
    """Get overall database statistics."""
    ioc_count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    pulse_count = conn.execute("SELECT COUNT(*) FROM pulses").fetchone()[0]
    vuln_count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    return {"iocs": ioc_count, "pulses": pulse_count, "vulnerabilities": vuln_count}


# --- Helpers ---


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
