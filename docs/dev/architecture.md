# Architecture

**Version:** v2.5.0 (homelab SOC / pentester triage)

ThreatScope is a privacy-first **homelab SOC gatekeeper**: local OSINT lookups, bulk IOC triage, static file analysis with YARA, content-addressed samples on disk, blocklist export, and optional MobSF or custom-script dynamic analysis. SQLite holds metadata only; summaries come from local Ollama; UI is HTMX + Jinja2.

---

## System diagram

```
Browser (HTMX)
    │
    ▼
FastAPI (main.py)
    ├── Data layer       → SQLite (database.py) — indicators + indicator_sources
    ├── Freshness        → services/freshness.py — TTL active/stale per feed
    ├── Bulk / export    → services/bulk_lookup.py, services/export_blocklist.py
    ├── Feed ingest      → ingest_feeds.py (cron, standalone CLI)
    ├── Intel collection → ingest_intel.py / intel_worker.py (optional; reads intel_feeds.yaml)
    ├── Intel search     → intel_items + FTS5 (admin: THREATSCOPE_ADMIN=1)
    ├── File analysis    → services/static_analysis.py + static_documents.py + yara_scan.py
    ├── File reports     → services/file_analysis.py (UNKNOWN verdict when no signals)
    ├── Escalation       → services/escalation.py → Next steps panel
    ├── Sample store     → data/samples/<sha256> (services/sample_store.py)
    ├── Sandbox jobs     → analysis_jobs table + scripts/sandbox_worker.py
    ├── Sandbox adapters → services/sandbox/ (mock, MobSF, script, CAPE optional)
    ├── Intelligence     → Ollama (services/ai_analyst.py) — 2 sentences + ACTION bullets
    └── Presentation     → Jinja2 HTML partials

Cron (optional)
    ├── ingest_feeds.py → OSINT indicators (daily / --if-changed)
    └── ingest_intel.py → intel_items narratives + IOC extract (IOC-only for leaks)
```

Legacy V1 API clients (`services/abuseipdb.py`, `virustotal.py`, etc.) remain in the repo but are **not used**.

---

## Technology stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.10+, FastAPI, Jinja2Templates, aiosqlite, httpx |
| AI | Ollama REST API (`127.0.0.1:11434`), model `qwen2.5:1.5b` |
| Frontend | HTML5, HTMX 2.x (CDN), Tailwind CSS (CDN) |
| Feeds | 10+ OSINT sources (Blocklist.de, URLhaus, MalwareBazaar, etc.) |
| File analysis | pefile (PE), zipfile + optional androguard (APK), static_documents (ZIP/PDF/Office), yara-python |
| YARA rules | On disk under `data/yara_rules/`; sync via `ingest_yara_rules.py` |

**Strict rules:**

- No React, Vue, or npm packages
- Tailwind utility classes only (via CDN)
- Parameterized SQL queries only
- Files uploaded for analysis are never executed

---

## Database (summary)

Full CRUD reference in [database.md](database.md):

| Table | Purpose |
|-------|---------|
| `indicators` | Primary intel records — PK `(value, type)` |
| `indicator_sources` | Per-feed `last_seen` for snapshot ingest + freshness TTL |
| `feed_sync_state` | ETag / content hash for `--if-changed` ingest |
| `analysis_jobs` | Dynamic sandbox queue |
| `file_samples` | Upload metadata by SHA256 (blobs on disk) |
| `lookup_history` | Recent indicator/file lookups |
| `intel_items` | Collected intel documents (RSS/paste/leak); FTS via `intel_items_fts` |
| `collector_runs` | Per-run stats for intel ingest |

Pragmas: WAL journal, `foreign_keys=ON`, shared read connection pool.

---

## API endpoints

| Method | Path | Returns | Notes |
|--------|------|---------|-------|
| GET | `/` | HTML dashboard | Sets CSRF cookie |
| GET | `/health` | JSON | `{status, timestamp}` |
| POST | `/api/lookup` | HTML partial | Indicator search |
| POST | `/api/bulk-lookup` | HTML partial | Up to 50 IOCs (CSRF) |
| GET | `/api/export/blocklist.csv` | CSV | `min_score`, `indicator_type`; rate-limited |
| POST | `/api/analyze-file` | HTML partial | File static + YARA (+ optional dynamic job) |
| GET | `/api/analysis-job/{id}` | HTML partial | Dynamic job poll / merged report |
| GET | `/api/history` | HTML partial | Recent lookup history (HTMX) |
| POST | `/api/intel-search` | HTML partial | FTS over `intel_items` (requires `THREATSCOPE_ADMIN=1`) |
| POST | `/api/ip` | HTML partial | Legacy IPv4-only |

All POST endpoints require CSRF token (double-submit cookie). Indicator lookups use POST only (no GET search).

---

## Version history

### V2.0 — Core dashboard

- Async SQLite, Jinja2 + HTMX UI, Ollama summaries, dev seeder

### V2.1 — Security hardening

- POST + CSRF, rate limiting, security headers, production mode, Ollama SSRF guard

### V2.2 — Multi-indicator support

- Unified `indicators` table (IPv4, IPv6, domain, hash), auto-detect UI, strict validation

### V2.3 — File analysis + feed ingest

- Static PE/APK analysis, `POST /api/analyze-file`, OSINT feed ingest

### V2.4 — Freshness & feed expansion

- `indicator_sources` table, snapshot prune, TTL-based stale verdicts, AI summary cache

### V2.5 — Pentester triage hub

- Bulk IOC paste, blocklist CSV export, Office/PDF/ZIP static, file UNKNOWN verdict, escalation panel, custom sandbox script backend, finding source tags

### V2.6 — Intel collection

- `ingest_intel.py` collectors (RSS, Pastebin, IntelX, DeHashed IOC-only), `intel_items` + FTS5, admin Intel tab, optional `intel_worker.py`

---

## File static analysis

| File type | Module | Checks |
|-----------|--------|--------|
| `.exe` | `static_analysis.py` (pefile) | PE structure, entropy, imports, strings |
| `.apk` | `static_analysis.py` (+ androguard) | Permissions, DEX, native libs, URLs |
| `.zip` | `static_documents.py` | Archive listing only (no extract/exec) |
| `.pdf` | `static_documents.py` | Byte scan; optional pdfid |
| Office | `static_documents.py` | Optional oletools for macros |
| All uploads | `yara_scan.py` | Signature match against `data/yara_rules/` |

Files are validated by magic bytes, size-capped, parsed in memory, stored by SHA256 under `data/samples/`, and never executed in the web process.

Findings carry a `source` tag: `signature` (YARA), `intel` (hash DB), or `heuristic` (PE/APK rules).

---

## Performance notes

- SQLite WAL mode + shared read connection pool
- Batch upsert (500 rows per executemany chunk)
- Parallel feed downloads via `asyncio.gather`
- Ollama summary cache (1h TTL) + concurrency semaphore (default 3)

---

## Dynamic sandbox

Optional second stage after static upload (APK-focused homelab path):

1. Web app stores sample by SHA256 and enqueues `analysis_jobs`
2. `scripts/sandbox_worker.py` reads `data/samples/<sha256>` and calls sandbox adapters
3. HTMX polls `GET /api/analysis-job/{id}` until `completed` or `failed`

| Backend | Use case |
|---------|----------|
| **mock** | CI and dev without Docker |
| **MobSF** | Homelab APK detonation (`docker compose --profile mobsf`) |
| **script** | User-provided analyzer — [custom-sandbox.md](custom-sandbox.md) |
| **CAPE** | Optional KVM lab for EXE (`SANDBOX_BACKEND=cape`) |

`SANDBOX_BACKEND=auto`: MobSF for `.apk` when reachable; **mock** for `.exe` (no CAPE probe).

---

## Roadmap

**Done**

- Bulk IOC paste (`POST /api/bulk-lookup`)
- Office / PDF / ZIP static analysis
- Blocklist CSV export
- Pentester escalation panel
- Custom sandbox script adapter
- Intel collection (RSS, paste/leak APIs, IOC-only; admin FTS search)

**Open**

- ThreatFox ingest when `ABUSE_CH_AUTH_KEY` is configured
- Telegram / Tor forum intel adapters (see [intel-collection.md](intel-collection.md))
- Webhook alerts (Slack/Discord on malicious hits)
- Optional CAPE homelab path for EXE detonation

---

## Related docs

- [development.md](development.md) — request flows, file map, conventions
- [intel-collection.md](intel-collection.md) — collectors, policy, CLI, cron
- [database.md](database.md) — schema, CRUD, feed lifecycle
- [custom-sandbox.md](custom-sandbox.md) — script backend contract
- [../user/feeds-and-analysis.md](../user/feeds-and-analysis.md) — user-facing feed & API docs
- [../ops/deployment.md](../ops/deployment.md) — VPS deployment
