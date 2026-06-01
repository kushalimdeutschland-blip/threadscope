# AGENTS.md — ThreatScope

Instructions for AI coding agents working in this repository.

## Start here

1. Read [`docs/dev/development.md`](docs/dev/development.md) — request flows, file map, conventions.
2. Read [`docs/dev/database.md`](docs/dev/database.md) — schema, CRUD, feed ingest lifecycle.
3. Skim [`docs/README.md`](docs/README.md) — full doc index.

## Project summary

Privacy-first homelab SOC gatekeeper: **FastAPI + HTMX + SQLite + Ollama + YARA**. OSINT via `ingest_feeds.py`; YARA rules on disk via `ingest_yara_rules.py`. Samples in `data/samples/` by SHA256, not in SQLite. Bulk IOC triage and blocklist CSV export. No React/npm.

## Critical rules

- Parameterized SQL only (`database.py`)
- POST + CSRF for all mutations; no GET lookups (except `GET /api/export/blocklist.csv` for CSV download)
- Feed writes use `bulk_upsert_feed_snapshot`, not `upsert_indicator`
- Never execute uploaded files in the web app (`main.py`); dynamic runs only via `scripts/sandbox_worker.py` + sandbox adapters
- Ollama URL locked to localhost
- Do not wire legacy `services/virustotal.py` etc. into `main.py`

## Key entry points

| Task | File |
|------|------|
| HTTP routes | `main.py` |
| DB operations | `database.py` |
| Feed ingest CLI | `ingest_feeds.py` |
| Sample hash ingest (lab) | `ingest_samples.py`, `services/sample_repos.py` |
| Intel collection CLI | `ingest_intel.py` |
| Intel collectors | `services/intel/` |
| Intel AI (Ollama) | `services/intel/ai.py`, `services/intel/context.py` |
| YARA rules sync | `ingest_yara_rules.py` |
| Feed parsers | `services/feed_parser.py` |
| Lookup logic | `services/lookup.py` + `services/freshness.py` |
| Bulk IOC | `services/bulk_lookup.py` |
| Blocklist export | `services/export_blocklist.py` |
| File reports / UNKNOWN verdict | `services/file_analysis.py` |
| Escalation panel | `services/escalation.py` |
| Static + YARA | `services/static_analysis.py`, `services/yara_scan.py`, `services/static_documents.py` |
| Custom sandbox | `docs/dev/custom-sandbox.md`, `services/sandbox/script_adapter.py` |
| UI | `templates/index.html`, `templates/partials/` |

## Run

```bash
source venv/bin/activate
python ingest_feeds.py
python ingest_yara_rules.py   # optional
./scripts/dev.sh
```

## VPS (public tier)

- On-server bootstrap: `scripts/vps-bootstrap.sh` — see [docs/ops/vps-manual-setup.md](docs/ops/vps-manual-setup.md)
- Lab hash DB → VPS: `scripts/sync-hash-db-to-production.sh` (stop `threatscope` first)
- Do **not** run `ingest_samples.py` on the public VPS
