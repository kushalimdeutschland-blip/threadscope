# Development Guide

Read this before modifying the codebase.

| Topic | Doc |
|-------|-----|
| Database & ingest | [database.md](database.md) |
| Intel collection | [intel-collection.md](intel-collection.md) |
| Architecture & roadmap | [architecture.md](architecture.md) |
| VPS deployment | [../ops/deployment.md](../ops/deployment.md) |
| User setup | [../user/quick-start.md](../user/quick-start.md) |

---

## What this project is

**ThreatScope** is a privacy-first homelab SOC gatekeeper:

- Lookups run against **local SQLite** (~500k indicators from OSINT feeds)
- **YARA** static scanning with rules on disk (`services/yara_scan.py`)
- **Ollama** generates file- or indicator-specific executive summaries
- **HTMX** dashboard — no React, no npm build
- **Static analysis** for PE/APK, ZIP (list-only), PDF, Office (parse-only, never executed); samples stored by SHA256 on disk
- **Bulk IOC** paste and **blocklist CSV** export for lab triage
- **Intel collection** (optional): RSS/paste/leak collectors out-of-process; admin FTS search over `intel_items`

Indicators never leave the server during lookup.

---

## Request flows

### Indicator search

```
GET /  → sets CSRF cookie + renders index.html
POST /api/lookup  (HTMX, form: q, indicator_type, csrf_token)
    → validate CSRF
    → resolve_indicator() in validation.py
    → lookup_indicator() in lookup.py
        → database.get_indicator + get_indicator_sources
        → freshness.evaluate_freshness()
    → ai_analyst.generate_threat_summary()  (2 sentences + 3 ACTION: bullets)
    → escalation panel for MALICIOUS / SUSPICIOUS / UNKNOWN / STALE
    → HTML partial: templates/partials/result.html

POST /api/bulk-lookup  (form: iocs, csrf_token — max 50 lines)
    → services/bulk_lookup.bulk_lookup_indicators()
    → HTML partial: templates/partials/bulk_result.html

GET /api/export/blocklist.csv  (query: min_score, indicator_type)
    → services/export_blocklist.export_blocklist_csv()
```

### File upload

```
POST /api/analyze-file  (multipart: file, csrf_token)
    → read_upload_file() — size cap, magic bytes
    → sample_store.store_sample() — content-addressed on disk
    → static_analysis.analyze_bytes() in thread pool (includes YARA)
    → database.upsert_file_sample() + record_lookup_history()
    → file_analysis.build_file_threat_report() — hash DB lookup
    → ai_analyst.generate_threat_summary() — file-specific prompt
    → escalation panel (copy IOCs / sample path / suggested CLI)
    → HTML partial: templates/partials/file_result.html
```

### Feed ingest (CLI, not HTTP)

```
python ingest_feeds.py
    → download feeds in parallel
    → feed_parser.parse_* → deduplicate
    → database.bulk_upsert_feed_snapshot per feed
```

### Intel collection (CLI, not HTTP)

```
python ingest_intel.py  (requires INTEL_COLLECTION_ENABLED=1)
    → services/intel/registry.py — enabled collectors from data/intel_feeds.yaml + .env keys
    → collectors fetch RSS/paste/leak text (parse only, never execute)
    → services/intel/extract.py — IOCs to bulk_upsert_feed_snapshot; passwords never stored
    → database.upsert_intel_item — narrative docs + FTS (intel_items / intel_items_fts)

POST /api/intel-search  (THREATSCOPE_ADMIN=1)
    → database.search_intel_items() → templates/partials/intel_result.html
    → analyst uses Search tab for indicators extracted from intel text
```

See [intel-collection.md](intel-collection.md).

---

## File map

| Path | Role |
|------|------|
| [`main.py`](../../main.py) | FastAPI app, routes, CSRF, rate limits, lifespan |
| [`config.py`](../../config.py) | Env settings (`Settings` dataclass) |
| [`database.py`](../../database.py) | SQLite schema, CRUD, feed bulk upsert |
| [`ingest_feeds.py`](../../ingest_feeds.py) | CLI feed downloader + ingest orchestrator |
| [`ingest_intel.py`](../../ingest_intel.py) | Intel collection CLI (RSS, paste, leak APIs) |
| [`data/intel_feeds.yaml`](../../data/intel_feeds.yaml) | Collector URLs and enable flags |
| `services/intel/` | Collectors, `extract.py` (IOC-only), registry |
| [`seed_db.py`](../../seed_db.py) | Dev sample data |
| `services/validation.py` | Input validation (IP, domain, hash) |
| `services/lookup.py` | Lookup + freshness → threat dict |
| `services/freshness.py` | TTL-based active/stale evaluation |
| `services/feed_parser.py` | OSINT text feed parsers |
| `services/ai_analyst.py` | Ollama client, cache, concurrency limit |
| `services/static_analysis.py` | PE/APK static analysis |
| `services/yara_scan.py` | YARA signature scanning |
| `services/sample_store.py` | SHA256-keyed sample files on disk |
| `ingest_yara_rules.py` | Conditional YARA bundle sync |
| `services/file_upload.py` | Secure upload handling |
| `services/file_analysis.py` | Merge static + hash DB; `file_verdict()` (UNKNOWN when no signals) |
| `services/bulk_lookup.py` | Parse up to 50 IOCs, parallel lookup |
| `services/export_blocklist.py` | CSV generation for export endpoint |
| `services/escalation.py` | Next-steps panel context for templates |
| `services/static_documents.py` | ZIP list, PDF/Office static (no execution) |
| `services/analysis_merge.py` | Merge static + dynamic job results |
| `services/csrf.py` | Double-submit CSRF tokens |
| [custom-sandbox.md](custom-sandbox.md) | Script backend contract (`SANDBOX_BACKEND=script`) |
| `middleware/security.py` | CSP, HSTS, body size limits |
| `templates/index.html` | Dashboard (File \| Search tabs) |
| `templates/partials/*.html` | HTMX response fragments |
| `static/app.js` | Tab + file upload UI (if split from index) |
| `services/abuseipdb.py` etc. | **Legacy V1** — unused, do not wire into main |

---

## Threat verdict logic

### Indicators — [`services/lookup.py`](../../services/lookup.py)

```python
score >= 70  → MALICIOUS
score >= 20  → SUSPICIOUS
else         → CLEAN
freshness == stale → STALE (effective score forced to 0)
not in DB    → UNKNOWN
```

### Files — [`services/file_analysis.py`](../../services/file_analysis.py) `file_verdict()`

```python
score >= 70  → MALICIOUS
score >= 20  → SUSPICIOUS
in_database or yara_match_count > 0 with low score → CLEAN
else         → UNKNOWN   # not in hash feeds and zero YARA matches
```

Static findings include `source`: `signature` (YARA), `intel` (hash DB), or `heuristic` (PE/APK rules).

### AI summaries — [`services/ai_analyst.py`](../../services/ai_analyst.py)

Separate prompts for files vs indicators. Output shape: **2 sentences** + **3 lines** starting with `ACTION:` for pentester next steps.

---

## Conventions

1. **SQL:** Parameterized queries only. Never f-string user input into SQL.
2. **Validation:** All external input through `services/validation.py` before DB write.
3. **Feed writes:** Use `bulk_upsert_feed_snapshot`, not raw `upsert_indicator`.
4. **UI responses:** HTMX endpoints return HTML partials, not JSON.
5. **Files:** Never execute uploaded binaries. Parse-only static analysis.
6. **Ollama URL:** Must remain localhost (SSRF guard in `ai_analyst.py`).
7. **No npm/React:** HTMX + Tailwind CDN + inline CSS variables in templates.
8. **Styling:** Dark mode via CSS variables in `index.html` — avoid custom Tailwind color names that CDN won't generate.

---

## Common tasks

### Run locally

```bash
source venv/bin/activate
python ingest_feeds.py          # populate DB
./scripts/start-ollama.sh       # terminal 1
./scripts/dev.sh                # terminal 2 → :8000
```

### Add a new indicator type

1. Extend `IndicatorType` in `database.py` + CHECK constraint (migration)
2. Add validator in `validation.py`
3. Update `resolve_indicator` / `detect_indicator_type`
4. Update `index.html` type pills + `main.py` form type
5. Update `result.html` if type-specific fields needed

### Change freshness TTL

Edit `SOURCE_TTL_DAYS` in [`services/freshness.py`](../../services/freshness.py).

### Change AI prompt

Edit `_INDICATOR_PROMPT` / `_FILE_PROMPT` in [`services/ai_analyst.py`](../../services/ai_analyst.py).

### Add a new feed

See checklist in [database.md](database.md#adding-a-new-feed-checklist).

### Phone, email, GeoIP, and lab scan

| Feature | Env / files | Module |
|---------|-------------|--------|
| Phone indicator type | `data/feeds/phone_scam.csv`, `ingest_feeds.py --feed phone_scam` | `validation.py`, `feed_parser.py` |
| Email indicator type | `data/feeds/email_scam.csv`, `ingest_feeds.py --feed email_scam` | `validation.py`, `feed_parser.py` |
| External phone API | `PHONE_LOOKUP_ENABLED=1`, `PHONE_LOOKUP_API_KEY` | `services/phone_intel.py` |
| Email DNS/MX (local) | default; optional `pip install dnspython` for MX | `services/email_intel.py` |
| External email API | `EMAIL_LOOKUP_ENABLED=1`, `EMAIL_LOOKUP_API_KEY` | `services/email_intel.py` |
| Passive GeoIP/DNS | `GEOLITE2_COUNTRY_PATH`, `GEOLITE2_ASN_PATH` | `services/enrichment.py` |
| Lab nmap/ping | `LAB_SCAN_ENABLED=1`, `scripts/scan_worker.py` | `services/lab_scan.py` |
| Intel collection | `INTEL_COLLECTION_ENABLED=1`, `ingest_intel.py`, `scripts/intel_worker.py` | `services/intel/`, [intel-collection.md](intel-collection.md) |
| Intel FTS UI | `THREATSCOPE_ADMIN=1` | `main.py` → `/api/intel-search` |

---

## Do NOT

- Call legacy V1 APIs (`virustotal.py`, `abuseipdb.py`, etc.) from `main.py`
- Expose Ollama port 11434 publicly
- Add GET-based lookup endpoints (leaks indicators to logs/referrers)
- Skip CSRF on POST routes
- Use `upsert_indicator` for feed ingest (loses smart merge)
- Delete rows from `indicators` during feed prune (only `indicator_sources` is pruned)
- Add npm/webpack/React without explicit user request

---

## Testing manually

```bash
# Health
curl -s http://127.0.0.1:8000/health

# Lookup via HTMX simulation
CSRF=$(curl -s -c /tmp/c.txt http://127.0.0.1:8000/ | grep -oP 'name="csrf_token" value="\K[^"]+')
curl -s -b /tmp/c.txt -X POST http://127.0.0.1:8000/api/lookup \
  -H "HX-Request: true" \
  -d "q=162.243.103.246&indicator_type=auto&csrf_token=$CSRF"

# Dry-run ingest
python ingest_feeds.py --dry-run
```
