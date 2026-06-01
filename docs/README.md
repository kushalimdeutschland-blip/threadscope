# ThreatScope Documentation

Privacy-first homelab SOC gatekeeper — **FastAPI + HTMX + SQLite + Ollama + YARA**.

**Version:** v2.5.0 · **Stack:** Python 3.10+, no npm/React

---

## Start here

| I want to… | Read |
|------------|------|
| Install and run locally | [user/quick-start.md](user/quick-start.md) |
| Configure environment variables | [user/configuration.md](user/configuration.md) |
| Understand feeds & file analysis | [user/feeds-and-analysis.md](user/feeds-and-analysis.md) |
| Enable intel collection (RSS, paste, leaks) | [dev/intel-collection.md](dev/intel-collection.md) |
| Deploy to a VPS | [ops/deployment.md](ops/deployment.md), [ops/vps-manual-setup.md](ops/vps-manual-setup.md) |
| Modify the codebase (human dev) | [dev/development.md](dev/development.md) |
| Work on SQLite / ingest (AI agent) | [dev/database.md](dev/database.md) + [../AGENTS.md](../AGENTS.md) |
| See architecture & roadmap | [dev/architecture.md](dev/architecture.md) |
| Lab sample hashes → public VPS | [dev/architecture-two-tier.md](dev/architecture-two-tier.md), [dev/sample-hash-ingest.md](dev/sample-hash-ingest.md) |
| Plug in a custom sandbox script | [dev/custom-sandbox.md](dev/custom-sandbox.md) |

---

## Documentation map

### User guides — `docs/user/`

| Doc | Contents |
|-----|----------|
| [quick-start.md](user/quick-start.md) | Prerequisites, install, pentester lab checklist, test lookups |
| [configuration.md](user/configuration.md) | `.env` variables, YARA paths, sandbox backends, security overview |
| [feeds-and-analysis.md](user/feeds-and-analysis.md) | OSINT ingest, intel collection overview, bulk IOC, blocklist export, static file analysis, API endpoints |

### Developer guides — `docs/dev/`

| Doc | Contents |
|-----|----------|
| [architecture.md](dev/architecture.md) | Stack, system diagram, version history, roadmap |
| [architecture-two-tier.md](dev/architecture-two-tier.md) | Lab ingest vs public VPS, DB sync |
| [sample-hash-ingest.md](dev/sample-hash-ingest.md) | `ingest_samples.py`, private git repos, hash upsert |
| [development.md](dev/development.md) | Request flows, file map, verdict logic, conventions |
| [database.md](dev/database.md) | Schema, CRUD, feed lifecycle, SQL examples |
| [custom-sandbox.md](dev/custom-sandbox.md) | `SANDBOX_BACKEND=script` contract and example |
| [intel-collection.md](dev/intel-collection.md) | RSS/paste/leak collectors, IOC-only policy, CLI, cron, admin Intel tab |

### Operations — `docs/ops/`

| Doc | Contents |
|-----|----------|
| [deployment.md](ops/deployment.md) | VPS checklist, Nginx, systemd, cron, attribution |
| [vps-manual-setup.md](ops/vps-manual-setup.md) | Copy-paste bootstrap when already SSH'd on the VPS |

### Root files

| File | Audience |
|------|----------|
| [../README.md](../README.md) | Project overview (GitHub landing page) |
| [../AGENTS.md](../AGENTS.md) | AI coding agents — quick rules & entry points |

---

## Project layout

```
threatscope/
├── main.py                 # FastAPI app + HTMX routes
├── config.py               # Environment settings
├── database.py             # Async SQLite
├── ingest_feeds.py         # OSINT feed CLI
├── ingest_intel.py         # Intel collection CLI (RSS, paste, leak APIs)
├── ingest_yara_rules.py    # YARA bundle sync
├── data/intel_feeds.yaml   # Intel collector URLs and enable flags
├── seed_db.py              # Dev sample data
├── services/               # Business logic
├── middleware/             # Security headers
├── templates/              # Jinja2 + HTMX UI
├── scripts/                # dev.sh, ingest-intel.sh, intel_worker.py, sandbox_worker.py
└── docs/                   # ← you are here
    ├── user/
    ├── dev/
    └── ops/
```
