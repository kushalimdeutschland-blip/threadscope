# ThreatScope

**A privacy-first homelab SOC gatekeeper** — local threat intel lookups, static file analysis with YARA, and optional MobSF detonation for APKs. Indicators and samples stay on your machine; summaries come from a **local Ollama** model, not commercial APIs.

Built with **FastAPI + HTMX + Tailwind (CDN)**. No npm, no React, no build step.

---

## What it does

1. Search **IPv4, IPv6, domains, or file hashes** against a local SQLite database (500k+ indicators from OSINT feeds).
2. **Bulk IOC paste** (up to 50 lines) for quick triage before deeper lab work.
3. Upload **`.exe`, `.apk`, `.zip`, `.pdf`, or Office** files for **parse-only static analysis** plus **YARA** (never executed in the web app).
4. Cross-check file hashes against **MalwareBazaar** and other ingested hash intel; **UNKNOWN** verdict when nothing matches (not “clean”).
5. Optionally detonate **APKs** in **MobSF** via an isolated worker (`sandbox_worker.py`), or plug in your own script backend.
6. **Next steps** panel — copy hashes, sample path, suggested CLI for Ghidra/strings on your lab VM.
7. Export a **blocklist CSV** for Suricata/Zeek or other lab tooling.
8. Optionally collect **narrative intel** (security RSS, paste APIs, IOC-only leak APIs) and search it on an admin **Intel** tab — extracted IOCs land in the same SQLite DB as OSINT feeds.
9. Get an AI analyst summary from Ollama (2 sentences + actionable **ACTION:** bullets).

This is **not** a VirusTotal clone. It is a **private, on-prem gatekeeper** for environments where telemetry must not leave the network.

---

## Key features

| Feature | Detail |
|---------|--------|
| Data sovereignty | Lookups and uploads stay on your server |
| OSINT feeds | 10+ feeds via `ingest_feeds.py` with `--if-changed` conditional sync |
| Bulk IOC triage | Paste up to 50 IOCs on the Search tab |
| Blocklist export | `GET /api/export/blocklist.csv` for lab blocklists |
| YARA static | Rules on disk (`data/yara_rules/`); sync via `ingest_yara_rules.py` |
| Static analysis | PE/APK, ZIP listing, PDF/Office (optional `oletools`/`pdfid`); samples by SHA256 on disk |
| MobSF dynamic | Opt-in APK sandbox; EXE uses static + YARA unless you run KVM CAPE or a custom script |
| Custom sandbox | `SANDBOX_BACKEND=script` — see [docs/dev/custom-sandbox.md](docs/dev/custom-sandbox.md) |
| AI summaries | File- and indicator-specific prompts with next-step actions |
| Lookup history | Recent searches on the dashboard |
| Intel collection | RSS + paste/leak APIs (IOC-only); `ingest_intel.py` + optional worker; admin FTS search |
| Security | CSRF, rate limits, CSP, parameterized SQL |

---

## Quick start

```bash
cd threatscope
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# System YARA library (Arch example)
sudo pacman -S yara

python ingest_feeds.py
python ingest_yara_rules.py   # optional full rule bundle; bootstrap rules work offline

./scripts/start-ollama.sh    # terminal 1
./scripts/dev.sh             # terminal 2 → http://127.0.0.1:8000
```

Full setup: **[docs/user/quick-start.md](docs/user/quick-start.md)**

**Deploy publicly** (personal site, rate-limited, no visitor accounts): copy [`.env.production.example`](.env.production.example), run [`scripts/predeploy-check.sh`](scripts/predeploy-check.sh), use [`deploy/nginx/threatscope.conf`](deploy/nginx/threatscope.conf) + [`deploy/systemd/threatscope.service`](deploy/systemd/threatscope.service). Details: **[docs/ops/deployment.md](docs/ops/deployment.md)**.

---

## Homelab dynamic analysis (MobSF)

```bash
docker compose --profile mobsf up
# .env: SANDBOX_BACKEND=auto or mobsf

python scripts/sandbox_worker.py   # separate terminal
```

Upload an `.apk`, enable **Run APK dynamic analysis**, and poll until MobSF completes. `.exe` files use static + YARA; CAPE is optional for dedicated KVM labs only. For custom automation, see **[docs/dev/custom-sandbox.md](docs/dev/custom-sandbox.md)**.

---

## Documentation

**[docs/README.md](docs/README.md)** — full index

| Guide | Doc |
|-------|-----|
| Install & run | [docs/user/quick-start.md](docs/user/quick-start.md) |
| Feeds & file analysis | [docs/user/feeds-and-analysis.md](docs/user/feeds-and-analysis.md) |
| Intel collection | [docs/dev/intel-collection.md](docs/dev/intel-collection.md) |
| Architecture | [docs/dev/architecture.md](docs/dev/architecture.md) |
| VPS deployment | [docs/ops/deployment.md](docs/ops/deployment.md) |

---

## Roadmap

- [x] OSINT feed ingest + conditional sync
- [x] Static file analysis + YARA
- [x] Content-addressed sample storage
- [x] MobSF dynamic (APK) + mock for CI
- [x] Lookup history
- [x] File-specific AI prompts
- [x] Bulk IOC paste + blocklist CSV export
- [x] Office / PDF / ZIP static analysis
- [x] Pentester escalation panel + custom sandbox adapter
- [x] Intel collection (RSS, paste/leak APIs, IOC-only; admin search tab)
- [ ] Optional ThreatFox via `ABUSE_CH_AUTH_KEY` (ingest when key is set)
- [ ] Slack/webhook alerts
