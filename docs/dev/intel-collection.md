# Intel collection

Background pipeline for **narrative intel** (RSS security news, allowlisted web scrape, paste APIs, IOC-only leak APIs) separate from public OSINT [`ingest_feeds.py`](../../ingest_feeds.py).

## Policy

- **IOC-only for leaks:** emails (and other IOCs from paste/RSS text) go to `indicators` via `bulk_upsert_feed_snapshot`. **Passwords and credential pairs are never stored** — leak parsers use `parse_leak_row()` in [`services/intel/extract.py`](../../services/intel/extract.py).
- **Sanitization (required):** all titles, bodies, and meta pass through [`services/intel/sanitize.py`](../../services/intel/sanitize.py) before SQLite, FTS5, and UI. HTML/scripts stripped, secrets redacted, null bytes removed, body truncated to `INTEL_MAX_BODY_BYTES`. Dedup via `body_sha256` on sanitized body only.
- **No execution:** collectors parse text/JSON/RSS/HTML only; the web app never runs scraped content.
- **Out-of-process:** run `ingest_intel.py` or `scripts/intel_worker.py` on a schedule; FastAPI only reads SQLite.

## Configuration

| Variable | Purpose |
|----------|---------|
| `INTEL_COLLECTION_ENABLED=1` | Required to run ingest CLI/worker |
| `INTELX_API_KEY` | Intelligence X search API |
| `PASTEBIN_API_KEY` | Pastebin scraping API dev key |
| `DEHASHED_API_KEY` / `DEHASHED_API_EMAIL` | Optional DeHashed (IOC-only adapter) |
| `INTEL_WORKER_INTERVAL` | Daemon sleep seconds (default 3600) |
| `INTEL_MAX_BODY_BYTES` | Max document body size (default 32768) |
| `INTEL_SCRAPE_RESPECT_ROBOTS` | Honor robots.txt for web scrape (default true) |
| `INTEL_SCRAPE_DELAY_SECONDS` | Min seconds between requests per domain (default 2) |
| `INTEL_LIST_SNIPPET_CHARS` | Intel UI search snippet length (default 240) |
| `INTEL_LIST_BODY_CHARS` | Intel UI expandable body cap (default 4000) |
| `THREATSCOPE_ADMIN=1` | Enables **Intel** search tab (`POST /api/intel-search`) |

Feed URLs and enable flags: [`data/intel_feeds.yaml`](../../data/intel_feeds.yaml). API keys stay in `.env` only.

### `intel_feeds.yaml` sections

| Section | CLI `--collector` | Notes |
|---------|-------------------|--------|
| `rss` | `rss` | Public RSS/Atom (`enabled: true` by default) |
| `web` | `web` | Allowlisted HTML pages; set `web.enabled: true` and per-target `enabled: true` after ToS review |
| `paste` | `paste` | Needs `PASTEBIN_API_KEY` |
| `intelx` | `intelx` | Needs `INTELX_API_KEY` |
| `leak.dehashed` | `leak` | Needs `DEHASHED_API_KEY`; IOC emails only |

## Run

```bash
source venv/bin/activate
pip install -r requirements.txt   # feedparser, PyYAML, beautifulsoup4

# One-shot (cron)
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py --if-changed
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py --collector rss --dry-run
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py --collector web --dry-run

# Wrapper
./scripts/ingest-intel.sh --if-changed

# Optional daemon
INTEL_COLLECTION_ENABLED=1 python scripts/intel_worker.py
```

Example cron (hourly, skip unchanged):

```cron
0 * * * * cd /opt/threatscope && INTEL_COLLECTION_ENABLED=1 ./scripts/ingest-intel.sh --if-changed >> /var/log/threatscope-intel.log 2>&1
```

## Collectors

| CLI name | Module | Notes |
|----------|--------|-------|
| `rss` | `collectors/rss_security.py` | Public RSS from yaml; conditional fetch |
| `web` | `collectors/web_scrape.py` | Allowlisted HTML → text; rate limit + optional robots.txt |
| `paste` | `collectors/paste_intelx.py` | Pastebin — needs `PASTEBIN_API_KEY` |
| `intelx` | `collectors/paste_intelx.py` | IntelX — needs `INTELX_API_KEY` |
| `leak` | `collectors/leak_api.py` | DeHashed — email IOCs only |

IOC extraction runs in `ingest_intel.py` on **sanitized** body text only.

## Intel AI (optional, local Ollama)

When `INTEL_AI_ENABLED=1`, ThreatScope can call **localhost Ollama only** on **sanitized** title/body text (never raw leak password fields):

| Sub-flag | Feature |
|----------|---------|
| `INTEL_AI_INGEST_SUMMARY=1` | One-line summary stored in `intel_items.meta.ai_summary` during `ingest_intel.py` |
| `INTEL_AI_LOOKUP_CONTEXT=1` | Up to 3 related intel snippets on `POST /api/lookup` (`meta.intel_context`) |
| `INTEL_AI_QUERY_EXPAND=1` | FTS query expansion on `POST /api/intel-search` |

Master default is **off** (`INTEL_AI_ENABLED=0`) so scheduled ingest stays fast. Skip summaries for one run: `python ingest_intel.py --no-ai`. Tune LLM input size with `INTEL_AI_MAX_BODY_CHARS` (default 4096).

Implementation: [`services/intel/ai.py`](../../services/intel/ai.py), [`services/intel/context.py`](../../services/intel/context.py).

## UI

With `THREATSCOPE_ADMIN=1`, the **Intel** tab runs FTS search over `intel_items`. Results show escaped snippets (with safe `<mark>` highlights), source badge, published date, IOC counts, YARA candidate tag, expandable sanitized body, and **Lookup** buttons for extracted emails/domains. Jinja2 autoescape is enabled; snippets are Markup only after escaping.

Extracted IOCs are in `indicators` (same DB as OSINT feeds) — use **Lookup** in intel results or the **Search** tab for `POST /api/lookup`.

User-facing summary: [feeds-and-analysis.md](../user/feeds-and-analysis.md#intel-collection-optional). Schema: [database.md](database.md#table-intel_items).

YARA: items tagged `yara_candidate` when rule-like text is detected — **manual** copy to `data/yara_rules/` only (no auto-write).

## Future (not MVP)

Telegram (Telethon), Tor/forum adapters, webhooks — see [architecture.md](architecture.md).
