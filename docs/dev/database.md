# Database Reference

ThreatScope stores all threat intelligence in **SQLite** at `data/threatscope.db` (gitignored). All access goes through [`database.py`](../../database.py) using **parameterized queries only**.

---

## Schema

### Table: `indicators`

Primary threat intel records. Composite primary key: `(value, type)`.

| Column | Type | Description |
|--------|------|-------------|
| `value` | TEXT | Normalized indicator (IP, domain, or hash) |
| `type` | TEXT | `ipv4` \| `ipv6` \| `domain` \| `hash` \| `phone` \| `email` |
| `risk_score` | INTEGER | 0–100 |
| `tags` | TEXT | JSON array of strings |
| `meta` | TEXT | JSON object (`source`, `sources`, `category`, etc.) |
| `last_updated` | TEXT | ISO 8601 UTC timestamp |

```sql
CREATE TABLE indicators (
    value        TEXT NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('ipv4', 'ipv6', 'domain', 'hash', 'phone', 'email')),
    risk_score   INTEGER NOT NULL DEFAULT 0,
    tags         TEXT NOT NULL DEFAULT '[]',
    meta         TEXT NOT NULL DEFAULT '{}',
    last_updated TEXT NOT NULL,
    PRIMARY KEY (value, type)
);
CREATE INDEX idx_indicators_type ON indicators(type);
```

### Table: `indicator_sources`

Per-feed tracking for snapshot ingest and freshness TTL. Composite PK: `(value, type, source)`.

| Column | Type | Description |
|--------|------|-------------|
| `value` | TEXT | FK → `indicators.value` |
| `type` | TEXT | FK → `indicators.type` |
| `source` | TEXT | Feed label (e.g. `URLhaus`, `Feodo Tracker`) |
| `last_seen` | TEXT | ISO 8601 UTC — updated on each feed snapshot |

```sql
CREATE TABLE indicator_sources (
    value     TEXT NOT NULL,
    type      TEXT NOT NULL,
    source    TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (value, type, source),
    FOREIGN KEY (value, type) REFERENCES indicators(value, type) ON DELETE CASCADE
);
```

**Pragmas:** WAL journal, `synchronous=NORMAL`, `foreign_keys=ON`.

### Table: `analyst_feedback`

Analyst verdict corrections tied to an indicator. FK `(value, type) → indicators` with `ON DELETE CASCADE`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-increment PK |
| `value` | TEXT | Indicator value |
| `type` | TEXT | Indicator type |
| `observed_verdict` | TEXT | Verdict ThreatScope showed |
| `expected_verdict` | TEXT | Verdict the analyst expects |
| `note` | TEXT | Optional comment |
| `created_at` | TEXT | ISO 8601 UTC |

Helpers: `insert_feedback`, `get_feedback_for_indicator`.

### Table: `feed_accuracy`

Per-feed TP/FP counts derived from analyst feedback joined to `indicator_sources`. `false_positive` means the analyst disagreed with ThreatScope, not strict ML FP.

| Column | Type | Description |
|--------|------|-------------|
| `source` | TEXT | Feed label (PK) |
| `true_positive` | INTEGER | Feedback where `observed_verdict == expected_verdict` |
| `false_positive` | INTEGER | Feedback where they differ |
| `last_updated` | TEXT | ISO 8601 UTC |

Helpers: `recompute_feed_accuracy`, `get_feed_accuracy`, `list_feed_accuracy`.

**Admin UI:** `GET /api/feed-accuracy` is homelab-only; enable with `THREATSCOPE_ADMIN=1` in the environment.

---

## CRUD operations

### Create / Update (single row)

```python
await database.upsert_indicator(
    value="185.220.101.45",
    indicator_type="ipv4",
    risk_score=97,
    tags=["Tor Exit Node", "Brute Force"],
    meta={"source": "manual"},
    last_updated=None,  # defaults to now UTC
)
```

- **Behavior:** `INSERT … ON CONFLICT DO UPDATE` — **full replace** of score, tags, meta.
- **Use for:** `seed_db.py`, manual admin scripts.
- **Do NOT use for feed ingest** — use `bulk_upsert_feed_snapshot` instead (smart merge).

Alias: `upsert_ip(ip, score, tags)` → `upsert_indicator(..., type="ipv4")`.

---

### Create / Update (feed snapshot — bulk)

```python
from services.feed_parser import FeedIndicator

rows = [
    FeedIndicator(
        value="1.2.3.4",
        type="ipv4",
        risk_score=85,
        tags=["URLhaus"],
        meta={"source": "URLhaus"},
    )
]
stats = await database.bulk_upsert_feed_snapshot(rows, source="URLhaus")
# stats.inserted, stats.updated, stats.skipped, stats.pruned
```

**Called by:** [`ingest_feeds.py`](../../ingest_feeds.py) once per feed.

**Insert (new row):**
- Sets `risk_score`, `tags`, `meta` (with `meta.sources = [source]`), `last_updated = now`.

**Update (existing row) — smart merge:**
- `risk_score` = `max(existing, incoming)`
- `tags` = union of existing + incoming (capped at 20)
- `meta.sources` = union of existing sources + new source
- `last_updated` = now

**Source tracking:**
- Upserts `indicator_sources (value, type, source, last_seen=now)`.

**Prune (snapshot cleanup):**
- After upsert, deletes `indicator_sources` rows for this `source` whose `(value, type)` are **not** in the current feed snapshot.
- Does **not** delete from `indicators` — stale rows remain for history; freshness logic zeroes effective score.

Batch size: **500** rows per `executemany` call.

---

### Read (single indicator)

```python
row = await database.get_indicator("162.243.103.246", "ipv4")
# None | {"value", "type", "risk_score", "tags", "meta", "last_updated"}
```

```python
sources = await database.get_indicator_sources("162.243.103.246", "ipv4")
# [{"source": "Feodo Tracker", "last_seen": "2026-05-26T..."}, ...]
```

**Read pool:** App startup opens a shared read connection (`open_read_pool()`). Writes use short-lived connections.

**Lookup pipeline:** [`services/lookup.py`](../../services/lookup.py) calls both functions, then [`services/freshness.py`](../../services/freshness.py) computes active vs stale.

---

### Read (lookup response shape)

After `lookup_indicator(value, type)`:

```python
{
    "value": str,
    "type": str,
    "risk_score": int,          # effective score (0 if stale)
    "stored_risk_score": int,   # raw DB score
    "verdict": str,             # MALICIOUS | SUSPICIOUS | CLEAN | STALE
    "tags": list[str],
    "meta": dict,
    "last_updated": str | None,
    "in_database": bool,
    "freshness_status": str,    # active | stale | none
    "last_seen_label": str,     # "today" | "3 days ago" | "—"
    "days_since_seen": int | None,
    "active_sources": list[dict],
    "all_sources": list[dict],
}
```

**Freshness TTL** ([`services/freshness.py`](../../services/freshness.py)):

| Source | TTL (days) |
|--------|------------|
| Phishing.Database | 30 |
| URLhaus, Feodo Tracker | 60 |
| Blocklist.de, CINSscore | 90 |
| Default (no source row) | 90 |

If `freshness_status == "stale"`: effective `risk_score = 0`, `verdict = "STALE"`.

---

### Delete

**No public delete API.** Indicators are never removed from `indicators` by design (historical intel).

**Partial delete:** Feed snapshot prune removes `indicator_sources` rows absent from the latest feed file:

```python
# Internal — called inside bulk_upsert_feed_snapshot
pruned_count = await _prune_feed_snapshot(db, source="URLhaus", keys=[(value, type), ...])
```

**Manual delete (admin only):**

```sql
-- Removes indicator AND cascaded source rows
DELETE FROM indicators WHERE value = ? AND type = ?;
```

There is no `database.delete_indicator()` helper yet — add one if needed.

---

## Feed ingest lifecycle

```
ingest_feeds.py
    │
    ├─ download feed (httpx, parallel)
    ├─ parse → list[FeedIndicator]     (services/feed_parser.py)
    ├─ deduplicate in memory           (keep max score per value+type)
    └─ bulk_upsert_feed_snapshot(rows, source=label)
           ├─ batch INSERT new indicators
           ├─ batch UPDATE existing (smart merge)
           ├─ upsert indicator_sources
           └─ prune stale source rows for this feed
```

### Feeds (hardcoded URLs in `ingest_feeds.py`)

| Key | Source label | Parser | Typical types |
|-----|--------------|--------|---------------|
| `blocklist` | Blocklist.de | `parse_blocklist_text` | ipv4, ipv6 |
| `cinsscore` | CINSscore | `parse_cinsscore_text` | ipv4, ipv6 |
| `urlhaus` | URLhaus | `parse_urlhaus_text` | ipv4, ipv6, domain |
| `phishing` | Phishing.Database | `parse_phishing_urls_text` | ipv4, domain |
| `feodo` | Feodo Tracker | `parse_feodo_text` | ipv4 |
| `malwarebazaar` | MalwareBazaar | `parse_malwarebazaar_csv` | hash |
| `spamhaus_drop` | Spamhaus DROP | `parse_spamhaus_drop_text` | ipv4 |
| `firehol` | FireHOL Level1 | `parse_firehol_level1_text` | ipv4 |
| `openphish` | OpenPhish | `parse_openphish_text` | ipv4, domain |
| `cisa_kev` | CISA KEV | `parse_cisa_kev_json` | ipv4, domain |
| `threatfox` | ThreatFox | `parse_threatfox_csv` | ipv4, domain, hash (optional) |

### Table: `intel_items`

Searchable intel documents from paste/leak APIs and clear-web RSS (`ingest_intel.py`). Composite unique key: `(source, source_id)`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER | Auto-increment PK |
| `source` | TEXT | Collector label (e.g. `RSS-BleepingComputer`, `IntelX`) |
| `source_id` | TEXT | Stable external id |
| `title` | TEXT | Headline |
| `body` | TEXT | Sanitized plain text only (HTML stripped, secrets redacted, truncated at ingest) |
| `url` | TEXT | Canonical link |
| `published_at` | TEXT | ISO UTC |
| `tags` | TEXT | JSON array (`cve`, `rat`, `leak`, …) |
| `meta` | TEXT | JSON (no passwords) |
| `ioc_count` | INTEGER | Denormalized extractor count |
| `body_sha256` | TEXT | SHA-256 of sanitized body; dedup skip when unchanged |
| `created_at` | TEXT | Ingest time |

**FTS5:** virtual table `intel_items_fts` on `title`, `body`, `tags` (external content + triggers). Search via `database.search_intel_items()` / `POST /api/intel-search` (admin-gated).

Helpers: `upsert_intel_item`, `get_intel_item`, `search_intel_items`, `create_collector_run`, `finish_collector_run`, `list_collector_runs`.

### Table: `collector_runs`

Per-run stats for intel ingest: `collector`, `started_at`, `finished_at`, `fetched`, `new_items`, `skipped`, `errors`, `error_text`.

### `feed_sync_state` table

Stores per-feed `etag`, `last_modified`, `content_sha256`, and ingest timestamps for `--if-changed` conditional downloads. See `services/feed_download.py`. Also used by `ingest_yara_rules.py` (`feed_key=yara_rules_bundle`) and intel collectors (`feed_key=intel:rss:…`, `intel:paste`, etc.).

### `file_samples` table

Metadata for uploaded files (blobs live under `data/samples/<sha2>/<sha256>`). Updated via `database.upsert_file_sample()` on each static analysis.

### `lookup_history` table

Recent indicator and file lookups for the dashboard history panel (`GET /api/history`). Written from `main.py` after successful lookup/upload.

### `analysis_jobs` table

Queue for dynamic sandbox jobs (`scripts/sandbox_worker.py`). Samples resolved by `file_hash` (SHA256) from the content-addressed store.

### Default risk scores (feed_parser.py)

| Feed | IPv4/IPv6 | Domain | Hash |
|------|-----------|--------|------|
| Feodo Tracker | 92 | — | — |
| MalwareBazaar / ThreatFox | — | — | 90 |
| Phishing.Database / OpenPhish | 88 | 88 | — |
| URLhaus / ThreatFox | 85–88 | 85–88 | — |
| Spamhaus DROP | 82 | — | — |
| CINSscore | 80 | — | — |
| FireHOL Level1 | 78 | — | — |
| Blocklist.de / CISA KEV | 75 | 75 | — |

---

## Validation before write

All values must pass [`services/validation.py`](../../services/validation.py) before insert:

| Type | Function | Notes |
|------|----------|-------|
| ipv4 | `validate_ipv4` | Canonical form via `ipaddress` |
| ipv6 | `validate_ipv6` | Strips `%scope` |
| domain | `validate_domain` | Lowercase, strips URL prefix/path |
| hash | `validate_hash` | MD5 (32), SHA1 (40), SHA256 (64) hex |

Feed parsers skip invalid lines silently.

---

## Dev seeding

```bash
python seed_db.py   # optional sample IPs/domains/hashes via upsert_indicator
```

Does not populate `indicator_sources` — seeded rows use `last_updated` only for freshness fallback.

---

## SQL examples (debugging)

```bash
sqlite3 data/threatscope.db
```

```sql
-- Count by type
SELECT type, COUNT(*) FROM indicators GROUP BY type;

-- Count by feed source
SELECT source, COUNT(*) FROM indicator_sources GROUP BY source ORDER BY 2 DESC;

-- Lookup one IP
SELECT * FROM indicators WHERE value = '162.243.103.246';
SELECT * FROM indicator_sources WHERE value = '162.243.103.246';

-- Recently ingested
SELECT value, type, risk_score, last_updated
FROM indicators ORDER BY last_updated DESC LIMIT 10;
```

---

## Adding a new feed (checklist)

1. Add URL to `FEEDS` and label to `FEED_LABELS` in [`ingest_feeds.py`](../../ingest_feeds.py).
2. Add parser in [`services/feed_parser.py`](../../services/feed_parser.py) returning `list[FeedIndicator]` with `meta={"source": "<label>"}`.
3. Register parser in `parse_feed()`.
4. Add TTL in `SOURCE_TTL_DAYS` in [`services/freshness.py`](../../services/freshness.py).
5. Run `python ingest_feeds.py --feed <key> --dry-run` then full ingest.
6. Update attribution in [ops/deployment.md](../ops/deployment.md) if public-facing.
