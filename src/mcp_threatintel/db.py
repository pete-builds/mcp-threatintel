"""SQLite database layer for threat intelligence cache.

Handles schema initialization, WAL mode, and provides upsert/query helpers
for IOCs, OTX pulses, CISA vulnerabilities, and feed sync tracking.
"""

import ast
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone


def _configure(conn: sqlite3.Connection) -> None:
    """Apply the standard per-connection configuration (WAL, busy_timeout, rows)."""
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")


def init_db(path: str) -> sqlite3.Connection:
    """Open a connection, ensure the schema exists, and return the connection.

    Used by the poller, which owns a single connection for the lifetime of one
    poll cycle (single-threaded). The MCP server should call this once at
    startup to create the schema, then use :func:`connect` per request rather
    than sharing this connection across threads.
    """
    conn = sqlite3.connect(path)
    _configure(conn)
    conn.executescript(SCHEMA)
    migrate_ioc_timestamps(conn)
    return conn


@contextmanager
def connect(path: str):
    """Open a short-lived, per-call SQLite connection as a context manager.

    Each MCP tool call opens its own connection and closes it on exit, so no
    sqlite3 connection is ever shared across threads (sqlite3 connections are
    not thread-safe by default, and FastMCP may dispatch tool calls on a
    threadpool). WAL mode and busy_timeout are reapplied per connection.

    Assumes the schema already exists (call :func:`init_db` once at startup).

    Example:
        with connect("/data/threatintel.db") as conn:
            rows = lookup_indicator(conn, "1.2.3.4")
    """
    conn = sqlite3.connect(path)
    _configure(conn)
    try:
        yield conn
    finally:
        conn.close()


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
    """Insert or update an IOC. Returns True if a new row was inserted.

    ``first_seen`` and ``last_seen`` are normalised to one UTC ISO-8601 shape
    (see :func:`normalize_ts`) so the time-window filters compare like with
    like. A missing ``last_seen`` falls back to ``first_seen``: feeds such as
    ThreatFox and MalwareBazaar send ``last_seen: null`` for indicators seen
    once, and a NULL ``last_seen`` would hide the row from every window.
    """
    kwargs = dict(kwargs)
    kwargs["first_seen"] = normalize_ts(kwargs.get("first_seen"))
    kwargs["last_seen"] = normalize_ts(kwargs.get("last_seen")) or kwargs["first_seen"]
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
    query = fts_query(query)
    if not query:
        return []
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
    query = fts_query(query)
    if not query:
        return []
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
    query = fts_query(query)
    if not query:
        return []
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


def fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 MATCH expression.

    FTS5 gives ``-``, ``.``, ``:``, ``?``, ``"``, ``*`` and ``^`` their own
    meaning, so a raw CVE id, IP, domain or question is a syntax error (or a
    column filter). Each whitespace-separated token becomes a quoted phrase
    with embedded double quotes doubled, which FTS5 treats purely as text;
    the phrases are ANDed, the FTS5 default. Returns "" when there is nothing
    to search for.
    """
    tokens = (text or "").split()
    return " ".join('"' + t.replace('"', '""') + '"' for t in tokens)


def normalize_ts(value) -> str | None:
    """Normalise a feed timestamp to ``YYYY-MM-DDTHH:MM:SS+00:00`` (UTC).

    Accepts the shapes the feeds send: ``2026-09-06 23:30:00 UTC`` (abuse.ch),
    ``2026-09-06 23:30:00`` (naive, read as UTC), a bare date (Feodo), and
    ISO-8601 with ``T``, ``Z`` or an offset. Empty input returns None; an
    unparseable value is returned unchanged rather than discarded.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    candidate = text
    if candidate.upper().endswith(" UTC"):
        candidate = candidate[:-4].strip()
    elif candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


# Raw-feed keys that may hold an IOC's timestamps, in preference order.
_RAW_FIRST_KEYS = ("first_seen", "first_seen_utc", "date_added")
_RAW_LAST_KEYS = ("last_seen", "last_seen_utc", "last_online")
_CANONICAL_TS = "____-__-__T__:__:__+00:00"


def _from_raw(raw: str | None, keys: tuple[str, ...]):
    if not raw:
        return None
    try:
        data = ast.literal_eval(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    for key in keys:
        if data.get(key):
            return data[key]
    return None


def migrate_ioc_timestamps(conn: sqlite3.Connection, batch: int = 2000) -> int:
    """Bring IOC rows written by older versions onto the normalised timestamps.

    Older builds stored feed timestamps verbatim (mixed formats) and read
    ThreatFox's timestamps from keys the API does not send, leaving both
    columns NULL. This rewrites any row whose ``first_seen``/``last_seen`` is
    NULL or not in canonical form, recovering missing values from
    ``raw_json`` where possible. Idempotent: a converted row no longer
    matches the selection. Commits in batches to keep write locks short.
    Returns the number of rows changed.
    """
    rows = conn.execute(
        """SELECT id, first_seen, last_seen, raw_json FROM iocs
           WHERE last_seen IS NULL OR last_seen NOT LIKE ?
              OR (first_seen IS NOT NULL AND first_seen NOT LIKE ?)""",
        (_CANONICAL_TS, _CANONICAL_TS),
    ).fetchall()
    changed = 0
    for row in rows:
        first = row["first_seen"] or _from_raw(row["raw_json"], _RAW_FIRST_KEYS)
        last = row["last_seen"] or _from_raw(row["raw_json"], _RAW_LAST_KEYS)
        new_first = normalize_ts(first)
        new_last = normalize_ts(last) or new_first
        if (new_first, new_last) == (row["first_seen"], row["last_seen"]):
            continue
        conn.execute(
            "UPDATE iocs SET first_seen = ?, last_seen = ? WHERE id = ?",
            (new_first, new_last, row["id"]),
        )
        changed += 1
        if changed % batch == 0:
            conn.commit()
    conn.commit()
    return changed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
