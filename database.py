"""
ThreatScope — async SQLite data layer (local OSINT lookups).
Supports IPv4, IPv6, domains, file hashes, phone numbers, and email addresses.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import aiosqlite

DB_PATH = Path(__file__).parent / "data" / "threatscope.db"
BATCH_SIZE = 500

IndicatorType = Literal["ipv4", "ipv6", "domain", "hash", "phone", "email"]

_CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    value        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('ipv4', 'ipv6', 'domain', 'hash', 'phone', 'email')),
    risk_score   INTEGER NOT NULL DEFAULT 0,
    tags         TEXT NOT NULL DEFAULT '[]',
    meta         TEXT NOT NULL DEFAULT '{}',
    last_updated TEXT NOT NULL,
    PRIMARY KEY (value, type)
);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);

CREATE TABLE IF NOT EXISTS indicator_sources (
    value     TEXT NOT NULL,
    type      TEXT NOT NULL,
    source    TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (value, type, source),
    FOREIGN KEY (value, type) REFERENCES indicators(value, type) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_indicator_sources_last_seen ON indicator_sources(last_seen);
CREATE INDEX IF NOT EXISTS idx_indicator_sources_source ON indicator_sources(source);

CREATE TABLE IF NOT EXISTS feed_sync_state (
    feed_key         TEXT PRIMARY KEY,
    etag             TEXT,
    last_modified    TEXT,
    content_sha256   TEXT,
    last_checked_at  TEXT,
    last_ingested_at TEXT,
    last_row_count   INTEGER
);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    id                 TEXT PRIMARY KEY,
    file_hash          TEXT NOT NULL,
    filename           TEXT NOT NULL,
    file_kind          TEXT NOT NULL,
    kind               TEXT NOT NULL DEFAULT 'dynamic',
    backend            TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'queued',
    external_job_id    TEXT,
    static_threat_json TEXT,
    report_json        TEXT,
    error_text         TEXT,
    created_at         TEXT NOT NULL,
    started_at         TEXT,
    finished_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status ON analysis_jobs(status);

CREATE TABLE IF NOT EXISTS file_samples (
    sha256           TEXT PRIMARY KEY,
    size_bytes       INTEGER NOT NULL,
    file_kind        TEXT,
    yara_match_count INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT NOT NULL,
    last_static_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lookup_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    query_value TEXT NOT NULL,
    query_type  TEXT NOT NULL,
    verdict     TEXT,
    risk_score  INTEGER,
    in_database INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookup_history_created ON lookup_history(created_at DESC);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id           TEXT PRIMARY KEY,
    target       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    resolved_ip  TEXT,
    status       TEXT NOT NULL DEFAULT 'queued',
    report_json  TEXT,
    error_text   TEXT,
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    value             TEXT NOT NULL,
    type              TEXT NOT NULL,
    observed_verdict  TEXT NOT NULL,
    expected_verdict  TEXT NOT NULL,
    note              TEXT,
    created_at        TEXT NOT NULL,
    FOREIGN KEY (value, type) REFERENCES indicators(value, type) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_feedback_value ON analyst_feedback(value, type);

CREATE TABLE IF NOT EXISTS feed_accuracy (
    source         TEXT PRIMARY KEY,
    true_positive  INTEGER NOT NULL DEFAULT 0,
    false_positive INTEGER NOT NULL DEFAULT 0,
    last_updated   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_items (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source       TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    body         TEXT NOT NULL DEFAULT '',
    url          TEXT,
    published_at TEXT,
    tags         TEXT NOT NULL DEFAULT '[]',
    meta         TEXT NOT NULL DEFAULT '{}',
    ioc_count    INTEGER NOT NULL DEFAULT 0,
    body_sha256  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    UNIQUE(source, source_id)
);
CREATE INDEX IF NOT EXISTS idx_intel_items_source ON intel_items(source);
CREATE INDEX IF NOT EXISTS idx_intel_items_published ON intel_items(published_at DESC);

CREATE VIRTUAL TABLE IF NOT EXISTS intel_items_fts USING fts5(
    title, body, tags,
    content='intel_items',
    content_rowid='id'
);

CREATE TABLE IF NOT EXISTS collector_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    collector   TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    fetched     INTEGER NOT NULL DEFAULT 0,
    new_items   INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    errors      INTEGER NOT NULL DEFAULT 0,
    error_text  TEXT
);
CREATE INDEX IF NOT EXISTS idx_collector_runs_collector ON collector_runs(collector, started_at DESC);
"""

JobStatus = Literal["queued", "running", "completed", "failed"]

_read_pool: aiosqlite.Connection | None = None
_pool_lock = asyncio.Lock()
_read_lock = asyncio.Lock()
BUSY_TIMEOUT_MS = 30_000


async def _configure_db(db: aiosqlite.Connection) -> None:
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    await db.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    db.row_factory = aiosqlite.Row


async def open_read_pool() -> None:
    global _read_pool
    async with _pool_lock:
        if _read_pool is None:
            _read_pool = await aiosqlite.connect(DB_PATH)
            await _configure_db(_read_pool)


async def close_read_pool() -> None:
    global _read_pool
    async with _pool_lock:
        if _read_pool is not None:
            await _read_pool.close()
            _read_pool = None


async def _get_read_connection() -> aiosqlite.Connection:
    await open_read_pool()
    assert _read_pool is not None
    return _read_pool


async def _new_write_connection() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    await _configure_db(db)
    return db


async def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = await _new_write_connection()
    try:
        await db.executescript(_CREATE_SCHEMA)
        await _migrate_legacy_ips(db)
        await _migrate_indicator_phone_type(db)
        await _migrate_indicator_email_type(db)
        await _migrate_intel_fts_triggers(db)
        await db.commit()
    finally:
        await db.close()
    await open_read_pool()


async def _migrate_legacy_ips(db: aiosqlite.Connection) -> None:
    """One-time migration from V2 threat_intel table."""
    async with db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='threat_intel'"
    ) as cursor:
        row = await cursor.fetchone()
    if not row:
        return

    await db.execute(
        """
        INSERT OR IGNORE INTO indicators (value, type, risk_score, tags, meta, last_updated)
        SELECT ip_address, 'ipv4', risk_score, tags, '{}', last_updated
        FROM threat_intel
        """
    )


async def _migrate_indicator_phone_type(db: aiosqlite.Connection) -> None:
    """Recreate indicators table if CHECK constraint lacks 'phone' type."""
    async with db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='indicators'"
    ) as cursor:
        row = await cursor.fetchone()
    if not row or not row[0]:
        return
    ddl = row[0]
    if "'phone'" in ddl:
        return

    await db.executescript(
        """
        CREATE TABLE IF NOT EXISTS indicators_new (
            value        TEXT NOT NULL,
            type         TEXT NOT NULL CHECK(type IN ('ipv4', 'ipv6', 'domain', 'hash', 'phone')),
            risk_score   INTEGER NOT NULL DEFAULT 0,
            tags         TEXT NOT NULL DEFAULT '[]',
            meta         TEXT NOT NULL DEFAULT '{}',
            last_updated TEXT NOT NULL,
            PRIMARY KEY (value, type)
        );
        INSERT INTO indicators_new SELECT * FROM indicators;
        DROP TABLE indicators;
        ALTER TABLE indicators_new RENAME TO indicators;
        CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
        """
    )


async def _migrate_indicator_email_type(db: aiosqlite.Connection) -> None:
    """Recreate indicators table if CHECK constraint lacks 'email' type."""
    async with db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='indicators'"
    ) as cursor:
        row = await cursor.fetchone()
    if not row or not row[0]:
        return
    ddl = row[0]
    if "'email'" in ddl:
        return

    await db.executescript(
        """
        CREATE TABLE IF NOT EXISTS indicators_new (
            value        TEXT NOT NULL,
            type         TEXT NOT NULL CHECK(type IN ('ipv4', 'ipv6', 'domain', 'hash', 'phone', 'email')),
            risk_score   INTEGER NOT NULL DEFAULT 0,
            tags         TEXT NOT NULL DEFAULT '[]',
            meta         TEXT NOT NULL DEFAULT '{}',
            last_updated TEXT NOT NULL,
            PRIMARY KEY (value, type)
        );
        INSERT INTO indicators_new SELECT * FROM indicators;
        DROP TABLE indicators;
        ALTER TABLE indicators_new RENAME TO indicators;
        CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
        """
    )


async def get_indicator(value: str, indicator_type: IndicatorType) -> dict[str, Any] | None:
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(
            """
            SELECT value, type, risk_score, tags, meta, last_updated
            FROM indicators WHERE value = ? AND type = ?
            """,
            (value, indicator_type),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


async def get_indicator_sources(value: str, indicator_type: IndicatorType) -> list[dict[str, Any]]:
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(
            """
            SELECT source, last_seen
            FROM indicator_sources
            WHERE value = ? AND type = ?
            ORDER BY last_seen DESC
            """,
            (value, indicator_type),
        ) as cursor:
            rows = await cursor.fetchall()
    return [{"source": row["source"], "last_seen": row["last_seen"]} for row in rows]


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return {
        "value": row["value"],
        "type": row["type"],
        "risk_score": row["risk_score"],
        "tags": json.loads(row["tags"]),
        "meta": json.loads(row["meta"]),
        "last_updated": row["last_updated"],
    }


async def upsert_indicator(
    value: str,
    indicator_type: IndicatorType,
    risk_score: int,
    tags: list[str],
    meta: dict[str, Any] | None = None,
    last_updated: str | None = None,
) -> None:
    ts = last_updated or datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO indicators (value, type, risk_score, tags, meta, last_updated)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(value, type) DO UPDATE SET
                risk_score = excluded.risk_score,
                tags = excluded.tags,
                meta = excluded.meta,
                last_updated = excluded.last_updated
            """,
            (value, indicator_type, risk_score, json.dumps(tags), json.dumps(meta or {}), ts),
        )
        await db.commit()
    finally:
        await db.close()


async def upsert_ip(ip_address: str, risk_score: int, tags: list[str], last_updated: str | None = None) -> None:
    await upsert_indicator(ip_address, "ipv4", risk_score, tags, last_updated=last_updated)


async def get_ip(ip_address: str) -> dict[str, Any] | None:
    return await get_indicator(ip_address, "ipv4")


def _merge_feed_indicator(
    existing: dict[str, Any],
    incoming: Any,
    now: str,
) -> tuple[int, list[str], dict[str, Any], str]:
    """Smart merge: max score, union tags, merge meta.sources."""
    from services.validation import MAX_TAGS, sanitize_tags

    risk_score = max(existing["risk_score"], incoming.risk_score)
    tags = sanitize_tags(list(dict.fromkeys(existing["tags"] + incoming.tags)))[:MAX_TAGS]

    meta = dict(existing.get("meta") or {})
    sources = list(meta.get("sources") or [])
    if meta.get("source"):
        sources.append(meta["source"])
    if incoming.meta.get("source"):
        sources.append(incoming.meta["source"])
    meta["sources"] = list(dict.fromkeys(s for s in sources if s))[:10]
    for key, val in incoming.meta.items():
        if key != "source":
            meta.setdefault(key, val)

    return risk_score, tags, meta, now


async def _fetch_existing_indicators(
    db: aiosqlite.Connection,
    keys: list[tuple[str, str]],
) -> dict[tuple[str, str], aiosqlite.Row]:
    if not keys:
        return {}

    existing: dict[tuple[str, str], aiosqlite.Row] = {}
    for i in range(0, len(keys), BATCH_SIZE):
        chunk = keys[i : i + BATCH_SIZE]
        placeholders = ", ".join("(?, ?)" for _ in chunk)
        params = [part for key in chunk for part in key]
        query = f"""
            SELECT value, type, risk_score, tags, meta
            FROM indicators
            WHERE (value, type) IN (VALUES {placeholders})
        """
        async with db.execute(query, params) as cursor:
            async for row in cursor:
                existing[(row["value"], row["type"])] = row
    return existing


async def _batch_upsert_indicators(
    db: aiosqlite.Connection,
    rows: list,
    now: str,
    stats: Any,
) -> list[Any]:
    from services.feed_parser import FeedIndicator

    valid = [row for row in rows if isinstance(row, FeedIndicator)]
    stats.skipped += len(rows) - len(valid)
    if not valid:
        return valid

    keys = [(row.value, row.type) for row in valid]
    existing_map = await _fetch_existing_indicators(db, keys)

    insert_sql = """
        INSERT INTO indicators (value, type, risk_score, tags, meta, last_updated)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    update_sql = """
        UPDATE indicators
        SET risk_score = ?, tags = ?, meta = ?, last_updated = ?
        WHERE value = ? AND type = ?
    """

    inserts: list[tuple[Any, ...]] = []
    updates: list[tuple[Any, ...]] = []

    for row in valid:
        key = (row.value, row.type)
        existing_row = existing_map.get(key)
        if existing_row is None:
            meta = dict(row.meta)
            if row.meta.get("source"):
                meta["sources"] = [row.meta["source"]]
            inserts.append(
                (row.value, row.type, row.risk_score, json.dumps(row.tags), json.dumps(meta), now)
            )
            stats.inserted += 1
        else:
            existing = {
                "risk_score": existing_row["risk_score"],
                "tags": json.loads(existing_row["tags"]),
                "meta": json.loads(existing_row["meta"]),
            }
            risk_score, tags, meta, ts = _merge_feed_indicator(existing, row, now)
            updates.append(
                (risk_score, json.dumps(tags), json.dumps(meta), ts, row.value, row.type)
            )
            stats.updated += 1

    for i in range(0, len(inserts), BATCH_SIZE):
        await db.executemany(insert_sql, inserts[i : i + BATCH_SIZE])
    for i in range(0, len(updates), BATCH_SIZE):
        await db.executemany(update_sql, updates[i : i + BATCH_SIZE])

    return valid


async def _upsert_indicator_sources(
    db: aiosqlite.Connection,
    rows: list,
    source: str,
    now: str,
) -> None:
    if not rows:
        return

    source_sql = """
        INSERT INTO indicator_sources (value, type, source, last_seen)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(value, type, source) DO UPDATE SET
            last_seen = excluded.last_seen
    """
    source_rows = [(row.value, row.type, source, now) for row in rows]
    for i in range(0, len(source_rows), BATCH_SIZE):
        await db.executemany(source_sql, source_rows[i : i + BATCH_SIZE])


async def _prune_feed_snapshot(
    db: aiosqlite.Connection,
    source: str,
    keys: list[tuple[str, str]],
) -> int:
    """Remove source rows for this feed that are absent from the current snapshot."""
    await db.execute("CREATE TEMP TABLE IF NOT EXISTS _snapshot_keys (value TEXT, type TEXT)")
    await db.execute("DELETE FROM _snapshot_keys")
    if keys:
        for i in range(0, len(keys), BATCH_SIZE):
            await db.executemany(
                "INSERT OR IGNORE INTO _snapshot_keys (value, type) VALUES (?, ?)",
                keys[i : i + BATCH_SIZE],
            )

    cursor = await db.execute(
        """
        DELETE FROM indicator_sources
        WHERE source = ?
        AND NOT EXISTS (
            SELECT 1 FROM _snapshot_keys sk
            WHERE sk.value = indicator_sources.value AND sk.type = indicator_sources.type
        )
        """,
        (source,),
    )
    return cursor.rowcount


async def bulk_upsert_feed_indicators(rows: list, source: str | None = None) -> "IngestStats":
    """
    Snapshot ingest for one feed: upsert indicators, track per-source last_seen,
    and prune entries removed from the feed since last run.
    """
    from services.feed_parser import IngestStats

    stats = IngestStats(parsed=len(rows))
    if not rows:
        return stats

    if source is None:
        source = rows[0].meta.get("source") if rows else None
    if not source:
        raise ValueError("Feed source name is required for snapshot ingest")

    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        valid = await _batch_upsert_indicators(db, rows, now, stats)
        await _upsert_indicator_sources(db, valid, source, now)
        keys = [(row.value, row.type) for row in valid]
        stats.pruned = await _prune_feed_snapshot(db, source, keys)
        await db.commit()
    finally:
        await db.close()

    return stats


async def bulk_upsert_feed_snapshot(rows: list, source: str) -> "IngestStats":
    """Alias for snapshot-aware feed ingest."""
    return await bulk_upsert_feed_indicators(rows, source=source)


async def get_feed_sync_state(feed_key: str) -> dict[str, Any] | None:
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(
            """
            SELECT feed_key, etag, last_modified, content_sha256,
                   last_checked_at, last_ingested_at, last_row_count
            FROM feed_sync_state WHERE feed_key = ?
            """,
            (feed_key,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def upsert_feed_sync_state(
    feed_key: str,
    *,
    etag: str | None = None,
    last_modified: str | None = None,
    content_sha256: str | None = None,
    checked: bool = True,
    ingested: bool = False,
    last_row_count: int | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    existing = await get_feed_sync_state(feed_key)
    db = await _new_write_connection()
    try:
        if existing is None:
            await db.execute(
                """
                INSERT INTO feed_sync_state (
                    feed_key, etag, last_modified, content_sha256,
                    last_checked_at, last_ingested_at, last_row_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feed_key,
                    etag,
                    last_modified,
                    content_sha256,
                    now if checked else None,
                    now if ingested else None,
                    last_row_count,
                ),
            )
        else:
            await db.execute(
                """
                UPDATE feed_sync_state SET
                    etag = COALESCE(?, etag),
                    last_modified = COALESCE(?, last_modified),
                    content_sha256 = COALESCE(?, content_sha256),
                    last_checked_at = CASE WHEN ? THEN ? ELSE last_checked_at END,
                    last_ingested_at = CASE WHEN ? THEN ? ELSE last_ingested_at END,
                    last_row_count = COALESCE(?, last_row_count)
                WHERE feed_key = ?
                """,
                (
                    etag,
                    last_modified,
                    content_sha256,
                    checked,
                    now,
                    ingested,
                    now,
                    last_row_count,
                    feed_key,
                ),
            )
        await db.commit()
    finally:
        await db.close()


# ── Analysis jobs (dynamic sandbox) ─────────────────────────────────────────


def _row_to_job(row: aiosqlite.Row) -> dict[str, Any]:
    data = dict(row)
    if data.get("static_threat_json"):
        data["static_threat"] = json.loads(data["static_threat_json"])
    else:
        data["static_threat"] = None
    if data.get("report_json"):
        data["report"] = json.loads(data["report_json"])
    else:
        data["report"] = None
    return data


async def create_analysis_job(
    job_id: str,
    *,
    file_hash: str,
    filename: str,
    file_kind: str,
    backend: str,
    static_threat: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    static_json = json.dumps(static_threat) if static_threat else None
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO analysis_jobs (
                id, file_hash, filename, file_kind, kind, backend, status,
                static_threat_json, created_at
            ) VALUES (?, ?, ?, ?, 'dynamic', ?, 'queued', ?, ?)
            """,
            (job_id, file_hash, filename, file_kind, backend, static_json, now),
        )
        await db.commit()
    finally:
        await db.close()
    job = await get_analysis_job(job_id)
    assert job is not None
    return job


async def get_analysis_job(job_id: str) -> dict[str, Any] | None:
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            "SELECT * FROM analysis_jobs WHERE id = ?",
            (job_id,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_job(row)


async def claim_next_analysis_job() -> dict[str, Any] | None:
    """Atomically claim oldest queued job for the sandbox worker."""
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        async with db.execute(
            """
            SELECT id FROM analysis_jobs
            WHERE status = 'queued'
            ORDER BY created_at ASC
            LIMIT 1
            """
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        job_id = row["id"]
        await db.execute(
            """
            UPDATE analysis_jobs
            SET status = 'running', started_at = ?
            WHERE id = ? AND status = 'queued'
            """,
            (now, job_id),
        )
        await db.commit()
        if db.total_changes == 0:
            return None
    finally:
        await db.close()
    return await get_analysis_job(job_id)


async def update_analysis_job(
    job_id: str,
    *,
    status: JobStatus | None = None,
    external_job_id: str | None = None,
    report: dict[str, Any] | None = None,
    error_text: str | None = None,
    finished: bool = False,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    fields: list[str] = []
    params: list[Any] = []

    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if external_job_id is not None:
        fields.append("external_job_id = ?")
        params.append(external_job_id)
    if report is not None:
        fields.append("report_json = ?")
        params.append(json.dumps(report))
    if error_text is not None:
        fields.append("error_text = ?")
        params.append(error_text)
    if finished:
        fields.append("finished_at = ?")
        params.append(now)

    if not fields:
        return

    params.append(job_id)
    db = await _new_write_connection()
    try:
        await db.execute(
            f"UPDATE analysis_jobs SET {', '.join(fields)} WHERE id = ?",
            params,
        )
        await db.commit()
    finally:
        await db.close()


async def count_running_analysis_jobs() -> int:
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            "SELECT COUNT(*) AS c FROM analysis_jobs WHERE status = 'running'"
        ) as cursor:
            row = await cursor.fetchone()
    return int(row["c"]) if row else 0


async def upsert_file_sample(
    sha256: str,
    *,
    size_bytes: int,
    file_kind: str | None,
    yara_match_count: int = 0,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO file_samples (sha256, size_bytes, file_kind, yara_match_count, first_seen, last_static_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                file_kind = COALESCE(excluded.file_kind, file_samples.file_kind),
                yara_match_count = excluded.yara_match_count,
                last_static_at = excluded.last_static_at
            """,
            (sha256.lower(), size_bytes, file_kind, yara_match_count, now, now),
        )
        await db.commit()
    finally:
        await db.close()


async def record_lookup_history(
    query_value: str,
    query_type: str,
    *,
    verdict: str | None,
    risk_score: int | None,
    in_database: bool,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO lookup_history (query_value, query_type, verdict, risk_score, in_database, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (query_value, query_type, verdict, risk_score, 1 if in_database else 0, now),
        )
        await db.commit()
    finally:
        await db.close()


async def list_indicators_for_export(
    *,
    min_score: int = 70,
    indicator_type: str = "all",
    limit: int = 50_000,
) -> list[dict[str, Any]]:
    """Rows for CSV blocklist export (malicious-tier scores)."""
    params: list[Any] = [min_score]
    type_clause = ""
    if indicator_type != "all":
        type_clause = " AND type = ?"
        params.append(indicator_type)
    params.append(limit)

    query = f"""
        SELECT value, type, risk_score, tags, last_updated
        FROM indicators
        WHERE risk_score >= ?{type_clause}
        ORDER BY risk_score DESC, value ASC
        LIMIT ?
    """
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        d = dict(row)
        d["tags"] = json.loads(d["tags"]) if d.get("tags") else []
        out.append(d)
    return out


async def insert_feedback(
    value: str,
    indicator_type: IndicatorType,
    observed_verdict: str,
    expected_verdict: str,
    note: str | None = None,
) -> None:
    """Insert one analyst feedback row. created_at = now UTC."""
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO analyst_feedback (
                value, type, observed_verdict, expected_verdict, note, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (value, indicator_type, observed_verdict, expected_verdict, note, now),
        )
        await db.commit()
    finally:
        await db.close()


async def get_feedback_for_indicator(value: str, indicator_type: IndicatorType) -> list[dict[str, Any]]:
    """Return all feedback rows for a given indicator, newest first."""
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            """
            SELECT id, value, type, observed_verdict, expected_verdict, note, created_at
            FROM analyst_feedback
            WHERE value = ? AND type = ?
            ORDER BY created_at DESC
            """,
            (value, indicator_type),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def recompute_feed_accuracy(source: str) -> None:
    """
    Count TP and FP across analyst_feedback for indicators that list this source.
    Upsert into feed_accuracy.
    """
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        async with db.execute(
            """
            SELECT
                SUM(CASE WHEN af.observed_verdict = af.expected_verdict THEN 1 ELSE 0 END) AS tp,
                SUM(CASE WHEN af.observed_verdict != af.expected_verdict THEN 1 ELSE 0 END) AS fp
            FROM analyst_feedback af
            INNER JOIN indicator_sources isrc
                ON af.value = isrc.value AND af.type = isrc.type
            WHERE isrc.source = ?
            """,
            (source,),
        ) as cursor:
            row = await cursor.fetchone()
        tp = int(row["tp"] or 0)
        fp = int(row["fp"] or 0)
        await db.execute(
            """
            INSERT INTO feed_accuracy (source, true_positive, false_positive, last_updated)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                true_positive = excluded.true_positive,
                false_positive = excluded.false_positive,
                last_updated = excluded.last_updated
            """,
            (source, tp, fp, now),
        )
        await db.commit()
    finally:
        await db.close()


async def get_feed_accuracy(source: str) -> dict[str, Any] | None:
    """Return the feed_accuracy row for source, or None."""
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            """
            SELECT source, true_positive, false_positive, last_updated
            FROM feed_accuracy
            WHERE source = ?
            """,
            (source,),
        ) as cursor:
            row = await cursor.fetchone()
    return dict(row) if row else None


async def list_feed_accuracy() -> list[dict[str, Any]]:
    """All feed_accuracy rows for admin view."""
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            """
            SELECT source, true_positive, false_positive, last_updated
            FROM feed_accuracy
            ORDER BY source ASC
            """
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def list_lookup_history(limit: int = 25) -> list[dict[str, Any]]:
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            """
            SELECT id, query_value, query_type, verdict, risk_score, in_database, created_at
            FROM lookup_history
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]


# ── Lab scan jobs (opt-in active scanning) ──────────────────────────────────


def _row_to_scan_job(row: aiosqlite.Row) -> dict[str, Any]:
    data = dict(row)
    if data.get("report_json"):
        data["report"] = json.loads(data["report_json"])
    else:
        data["report"] = None
    return data


async def create_scan_job(
    job_id: str,
    *,
    target: str,
    target_type: IndicatorType,
    resolved_ip: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO scan_jobs (id, target, target_type, resolved_ip, status, created_at)
            VALUES (?, ?, ?, ?, 'queued', ?)
            """,
            (job_id, target, target_type, resolved_ip, now),
        )
        await db.commit()
    finally:
        await db.close()
    job = await get_scan_job(job_id)
    assert job is not None
    return job


async def get_scan_job(job_id: str) -> dict[str, Any] | None:
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            "SELECT * FROM scan_jobs WHERE id = ?",
            (job_id,),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return _row_to_scan_job(row)


async def claim_next_scan_job() -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        async with db.execute(
            """
            SELECT id FROM scan_jobs
            WHERE status = 'queued'
            ORDER BY created_at ASC
            LIMIT 1
            """
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        job_id = row["id"]
        await db.execute(
            """
            UPDATE scan_jobs
            SET status = 'running', started_at = ?
            WHERE id = ? AND status = 'queued'
            """,
            (now, job_id),
        )
        await db.commit()
    finally:
        await db.close()
    return await get_scan_job(job_id)


async def update_scan_job(
    job_id: str,
    *,
    status: str | None = None,
    report: dict[str, Any] | None = None,
    error_text: str | None = None,
    finished: bool = False,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    fields: list[str] = []
    params: list[Any] = []

    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if report is not None:
        fields.append("report_json = ?")
        params.append(json.dumps(report))
    if error_text is not None:
        fields.append("error_text = ?")
        params.append(error_text)
    if finished:
        fields.append("finished_at = ?")
        params.append(now)

    if not fields:
        return

    params.append(job_id)
    db = await _new_write_connection()
    try:
        await db.execute(
            f"UPDATE scan_jobs SET {', '.join(fields)} WHERE id = ?",
            params,
        )
        await db.commit()
    finally:
        await db.close()


async def count_running_scan_jobs() -> int:
    db = await _get_read_connection()
    async with _read_lock:
        async with db.execute(
            "SELECT COUNT(*) AS c FROM scan_jobs WHERE status = 'running'"
        ) as cursor:
            row = await cursor.fetchone()
    return int(row["c"]) if row else 0


# ── Intel collection (documents + FTS5) ─────────────────────────────────────


_INTEL_FTS_TRIGGERS = """
CREATE TRIGGER IF NOT EXISTS intel_items_ai AFTER INSERT ON intel_items BEGIN
    INSERT INTO intel_items_fts(rowid, title, body, tags)
    VALUES (new.id, new.title, new.body, new.tags);
END;
CREATE TRIGGER IF NOT EXISTS intel_items_ad AFTER DELETE ON intel_items BEGIN
    INSERT INTO intel_items_fts(intel_items_fts, rowid, title, body, tags)
    VALUES ('delete', old.id, old.title, old.body, old.tags);
END;
CREATE TRIGGER IF NOT EXISTS intel_items_au AFTER UPDATE ON intel_items BEGIN
    INSERT INTO intel_items_fts(intel_items_fts, rowid, title, body, tags)
    VALUES ('delete', old.id, old.title, old.body, old.tags);
    INSERT INTO intel_items_fts(rowid, title, body, tags)
    VALUES (new.id, new.title, new.body, new.tags);
END;
"""


async def _migrate_intel_fts_triggers(db: aiosqlite.Connection) -> None:
    async with db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='intel_items'"
    ) as cursor:
        if not await cursor.fetchone():
            return
    await db.executescript(_INTEL_FTS_TRIGGERS)


def _intel_row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "source": row["source"],
        "source_id": row["source_id"],
        "title": row["title"],
        "body": row["body"],
        "url": row["url"],
        "published_at": row["published_at"],
        "tags": json.loads(row["tags"]),
        "meta": json.loads(row["meta"]),
        "ioc_count": row["ioc_count"],
        "body_sha256": row["body_sha256"],
        "created_at": row["created_at"],
    }


async def get_intel_item(source: str, source_id: str) -> dict[str, Any] | None:
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(
            """
            SELECT id, source, source_id, title, body, url, published_at,
                   tags, meta, ioc_count, body_sha256, created_at
            FROM intel_items WHERE source = ? AND source_id = ?
            """,
            (source, source_id),
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return _intel_row_to_dict(row)


async def upsert_intel_item(
    *,
    source: str,
    source_id: str,
    title: str,
    body: str,
    url: str | None = None,
    published_at: str | None = None,
    tags: list[str] | None = None,
    meta: dict[str, Any] | None = None,
    ioc_count: int = 0,
    body_sha256: str = "",
) -> tuple[str, int | None]:
    """Insert or update intel document; returns ('inserted'|'updated'|'skipped', id)."""
    import hashlib

    now = datetime.now(timezone.utc).isoformat()
    tags_json = json.dumps(tags or [])
    meta_json = json.dumps(meta or {})
    digest = body_sha256 or hashlib.sha256(body.encode("utf-8")).hexdigest()

    existing = await get_intel_item(source, source_id)
    if existing and existing.get("body_sha256") == digest:
        return ("skipped", existing["id"])

    db = await _new_write_connection()
    try:
        if existing is None:
            await db.execute(
                """
                INSERT INTO intel_items (
                    source, source_id, title, body, url, published_at,
                    tags, meta, ioc_count, body_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source,
                    source_id,
                    title,
                    body,
                    url,
                    published_at,
                    tags_json,
                    meta_json,
                    ioc_count,
                    digest,
                    now,
                ),
            )
            async with db.execute("SELECT last_insert_rowid() AS id") as cursor:
                row = await cursor.fetchone()
            item_id = int(row["id"]) if row else None
            await db.commit()
            return ("inserted", item_id)

        await db.execute(
            """
            UPDATE intel_items SET
                title = ?, body = ?, url = ?, published_at = ?,
                tags = ?, meta = ?, ioc_count = ?, body_sha256 = ?
            WHERE source = ? AND source_id = ?
            """,
            (
                title,
                body,
                url,
                published_at,
                tags_json,
                meta_json,
                ioc_count,
                digest,
                source,
                source_id,
            ),
        )
        await db.commit()
        return ("updated", existing["id"])
    finally:
        await db.close()


async def search_intel_items(
    query: str,
    *,
    tag: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """FTS5 search over intel documents (parameterized tag filter; sanitized MATCH)."""
    import re

    tokens = re.findall(r"[\w\-.]+", query, flags=re.UNICODE)
    if not tokens:
        return []
    match_expr = " ".join(f'"{t}"' for t in tokens[:32])
    params: list[Any] = [match_expr]
    tag_clause = ""
    if tag:
        tag_clause = " AND i.tags LIKE ?"
        params.append(f'%"{tag.strip().lower()}"%')
    params.append(min(max(limit, 1), 100))

    sql = f"""
        SELECT i.id, i.source, i.source_id, i.title, i.body, i.url,
               i.published_at, i.tags, i.meta, i.ioc_count, i.body_sha256, i.created_at,
               bm25(intel_items_fts) AS rank
        FROM intel_items_fts
        JOIN intel_items i ON i.id = intel_items_fts.rowid
        WHERE intel_items_fts MATCH ?{tag_clause}
        ORDER BY rank
        LIMIT ?
        """
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
    results = []
    for row in rows:
        item = _intel_row_to_dict(row)
        item["rank"] = row["rank"]
        results.append(item)
    return results


_IOC_INTEL_TYPES = frozenset({"email", "domain", "hash", "ipv4", "ipv6"})


def _fts_quote_token(value: str) -> str:
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


async def search_intel_items_for_ioc(
    value: str,
    *,
    indicator_type: str | None = None,
    limit: int = 3,
) -> list[dict[str, Any]]:
    """FTS search for intel documents mentioning an IOC (sanitized snippets only)."""
    from services.intel.sanitize import sanitize_for_display

    if indicator_type and indicator_type not in _IOC_INTEL_TYPES:
        return []

    import re

    needle = (value or "").strip()
    if len(needle) < 2:
        return []

    tokens = re.findall(r"[\w\-.@]+", needle, flags=re.UNICODE)
    if not tokens:
        return []
    match_expr = " ".join(_fts_quote_token(t) for t in tokens[:16])
    lim = min(max(limit, 1), 10)
    sql = """
        SELECT i.id, i.source, i.title, i.url, i.published_at, i.tags, i.meta, i.body
        FROM intel_items_fts
        JOIN intel_items i ON i.id = intel_items_fts.rowid
        WHERE intel_items_fts MATCH ?
        ORDER BY i.published_at DESC, i.created_at DESC
        LIMIT ?
        """
    async with _read_lock:
        db = await _get_read_connection()
        async with db.execute(sql, (match_expr, lim)) as cursor:
            rows = await cursor.fetchall()

    results: list[dict[str, Any]] = []
    for row in rows:
        meta = json.loads(row["meta"])
        body = row["body"] or ""
        snippet = meta.get("ai_summary")
        if not snippet:
            snippet = sanitize_for_display(body, max_len=200)
        results.append(
            {
                "id": row["id"],
                "title": row["title"],
                "source": row["source"],
                "url": row["url"],
                "published_at": row["published_at"],
                "tags": json.loads(row["tags"]),
                "snippet": snippet,
            }
        )
    return results


async def create_collector_run(collector: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            INSERT INTO collector_runs (collector, started_at)
            VALUES (?, ?)
            """,
            (collector, now),
        )
        async with db.execute("SELECT last_insert_rowid() AS id") as cursor:
            row = await cursor.fetchone()
        await db.commit()
        return int(row["id"]) if row else 0
    finally:
        await db.close()


async def finish_collector_run(
    run_id: int,
    *,
    fetched: int = 0,
    new_items: int = 0,
    skipped: int = 0,
    errors: int = 0,
    error_text: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    db = await _new_write_connection()
    try:
        await db.execute(
            """
            UPDATE collector_runs SET
                finished_at = ?, fetched = ?, new_items = ?,
                skipped = ?, errors = ?, error_text = ?
            WHERE id = ?
            """,
            (now, fetched, new_items, skipped, errors, error_text, run_id),
        )
        await db.commit()
    finally:
        await db.close()


async def list_collector_runs(collector: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    limit = min(max(limit, 1), 100)
    async with _read_lock:
        db = await _get_read_connection()
        if collector:
            sql = """
                SELECT id, collector, started_at, finished_at, fetched, new_items,
                       skipped, errors, error_text
                FROM collector_runs WHERE collector = ?
                ORDER BY started_at DESC LIMIT ?
                """
            params: tuple[Any, ...] = (collector, limit)
        else:
            sql = """
                SELECT id, collector, started_at, finished_at, fetched, new_items,
                       skipped, errors, error_text
                FROM collector_runs
                ORDER BY started_at DESC LIMIT ?
                """
            params = (limit,)
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]
