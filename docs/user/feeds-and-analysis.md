# Feeds & File Analysis

---

## OSINT feed ingest

Populate or refresh the local database from public OSINT feeds (most require no API key):

```bash
python ingest_feeds.py                    # all feeds (force download, default)
python ingest_feeds.py --if-changed     # skip feeds unchanged since last check
python ingest_feeds.py --feed blocklist   # single feed
python ingest_feeds.py --dry-run          # parse only, no DB writes
./scripts/ingest-feeds.sh --if-changed    # cron wrapper (passes CLI flags)
```

Example output:

```
Downloading 10 feed(s) (if-changed) ...
  Unchanged: Blocklist.de
  Ingested 12,000 hashes from MalwareBazaar (pruned 0 stale source rows)

Checked 10 feed(s): 2 updated, 8 unchanged, 0 failed
Done. Inserted: 12,000 | Updated: 1,200 | Pruned: 50 | Skipped: 0
```

### Feed sources

| Feed key | Source | Indicators extracted |
|----------|--------|----------------------|
| `blocklist` | [Blocklist.de all.txt](https://lists.blocklist.de/lists/all.txt) | IPv4/IPv6 |
| `cinsscore` | [CINSscore ci-badguys](https://cinsscore.com/list/ci-badguys.txt) | IPv4/IPv6 |
| `urlhaus` | [URLhaus text](https://urlhaus.abuse.ch/downloads/text/) | Domains + IPs from malware URLs |
| `phishing` | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | Domains from active phishing URLs |
| `feodo` | [Feodo Tracker](https://feodotracker.abuse.ch/downloads/ipblocklist.txt) | Botnet C2 IPv4 |
| `malwarebazaar` | [MalwareBazaar recent CSV](https://bazaar.abuse.ch/export/csv/recent/) | MD5, SHA1, SHA256 hashes |
| `spamhaus_drop` | [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) | IPv4 from DROP list |
| `firehol` | [FireHOL level1](https://github.com/firehol/blocklist-ipsets) | Aggregated IPv4 blocklist |
| `openphish` | [OpenPhish feed](https://openphish.com/feed.txt) | Domains + IPs from phishing URLs |
| `cisa_kev` | [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | IPs/domains parsed from advisory text |
| `threatfox` | ThreatFox export (optional) | IPs, domains, hashes — requires `ABUSE_CH_AUTH_KEY` |
| `phone_scam` | Local `data/feeds/phone_scam.csv` | E.164 phone numbers (homelab-maintained) |
| `email_scam` | Local `data/feeds/email_scam.csv` | Normalized email addresses (homelab-maintained) |

Set a free abuse.ch auth key for ThreatFox:

```bash
export ABUSE_CH_AUTH_KEY="your-key"   # https://auth.abuse.ch/
python ingest_feeds.py --feed threatfox
```

Phone scam list (local file, no download):

```bash
# Edit data/feeds/phone_scam.csv — columns: phone,score,tags,source
python ingest_feeds.py --feed phone_scam
```

Email scam list (local file, no download):

```bash
# Edit data/feeds/email_scam.csv — columns: email,score,tags,source
python ingest_feeds.py --feed email_scam
```

### Conditional sync (`--if-changed`)

Each feed’s HTTP validators (`ETag`, `Last-Modified`) and a content SHA-256 hash are stored in `feed_sync_state`. When you run with `--if-changed`, feeds that return `304 Not Modified` or an identical body hash are skipped (no parse/upsert). The Phishing.Database feed uses the GitHub commit SHA as an extra check.

Use **`--force`** (default) for a full refresh, or **`--if-changed`** on a frequent cron after the first full ingest.

### Upsert & freshness

Each feed run is a **snapshot**:

- Existing indicators get refreshed timestamps; tags merged; highest risk score kept
- Indicators removed from a feed are pruned from that **source** (not deleted from DB)
- Lookups use per-source TTLs to mark intel **active** vs **stale**
- Indicators with **no local match** show verdict **UNKNOWN** (UI label: “NO LOCAL DATA”; not “clean”)

| Source | TTL (days) |
|--------|------------|
| Phishing.Database / OpenPhish | 30 |
| URLhaus / Feodo / MalwareBazaar / ThreatFox | 60 |
| Blocklist.de / CINSscore / Spamhaus DROP / FireHOL | 90 |
| CISA KEV | 180 |

Stale indicators show **NOT CURRENTLY LISTED** in the UI.

Ollama summaries are cached for 1 hour; concurrent AI requests capped at 3.

Developer details: [dev/database.md](../dev/database.md)

### Cron (production)

```cron
# Daily full ingest (safety net)
0 4 * * * /opt/threatscope/scripts/ingest-feeds.sh --force >> /var/log/threatscope-ingest.log 2>&1

# Every 6 hours — skip unchanged feeds
0 */6 * * * /opt/threatscope/scripts/ingest-feeds.sh --if-changed >> /var/log/threatscope-ingest.log 2>&1
```

### Attribution

Required for public deployment. Credit:

> Threat intelligence data courtesy of [abuse.ch](https://abuse.ch), [Blocklist.de](https://www.blocklist.de/), [CINSscore](https://cinsscore.com/), [Spamhaus](https://www.spamhaus.org/), [OpenPhish](https://openphish.com/), [FireHOL](https://github.com/firehol/blocklist-ipsets), [CISA](https://www.cisa.gov/), and [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database).

See [ops/deployment.md](../ops/deployment.md) for abuse.ch and Spamhaus terms.

---

## Intel collection (optional)

Background pipeline for **narrative intel** — security RSS, optional allowlisted web scrape, paste APIs (Pastebin, Intelligence X), and optional leak APIs (e.g. DeHashed). Runs **out-of-process** via CLI; the web app only reads SQLite.

| Aspect | Detail |
|--------|--------|
| vs OSINT feeds | `ingest_feeds.py` = public blocklists/hashes; `ingest_intel.py` = articles/pastes with FTS search |
| Sanitization | HTML stripped, secrets redacted, bodies truncated; only sanitized text is stored and shown |
| IOC policy | Emails, domains, IPs, hashes from **sanitized** text go to `indicators`. **Passwords and credential pairs are never stored.** |
| Enable | `INTEL_COLLECTION_ENABLED=1`, API keys in `.env`, URLs/flags in `data/intel_feeds.yaml` |
| Run | `python ingest_intel.py`, `./scripts/ingest-intel.sh --if-changed`, or `python scripts/intel_worker.py` |
| UI | `THREATSCOPE_ADMIN=1` → **Intel** tab (FTS, snippets, Lookup IOC buttons). Open **Search** for full triage. |

```bash
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py --if-changed
INTEL_COLLECTION_ENABLED=1 python ingest_intel.py --collector rss --dry-run
./scripts/ingest-intel.sh --if-changed
```

Example cron (hourly, skip unchanged):

```cron
0 * * * * cd /opt/threatscope && INTEL_COLLECTION_ENABLED=1 ./scripts/ingest-intel.sh --if-changed >> /var/log/threatscope-intel.log 2>&1
```

Full reference: [dev/intel-collection.md](../dev/intel-collection.md)

---

## Indicator triage (Search tab)

### Single lookup

Use the main search box for one IPv4, IPv6, domain, or hash. URLs are normalized to host/IP where possible (e.g. `https://evil.com/path` → domain).

Indicators with **no local match** show **UNKNOWN** (not “clean”). Stale feed rows show **STALE** / **NOT CURRENTLY LISTED**.

### Bulk IOC paste and file import

On the Search tab, open **Bulk IOC lookup** and either:

- **Paste** up to **50** IOCs (one per line, or comma/semicolon separated), or
- **Import** a `.txt`, `.csv`, or `.list` file (max **256 KiB**, text/UTF-8 only).

For CSV, the first column is used unless a header row names a column `value`, `ioc`, or `indicator`.

- Paste: `POST /api/bulk-lookup` — form fields `iocs`, `csrf_token`
- File: `POST /api/bulk-lookup-file` — multipart `file`, `csrf_token`
- Returns an HTML table of verdicts per IOC

### Blocklist CSV export

Export high-confidence local indicators for lab blocklists (Suricata, Zeek, firewall drops):

```text
GET /api/export/blocklist.csv?min_score=70&indicator_type=all
```

| Query param | Default | Description |
|-------------|---------|-------------|
| `min_score` | `70` | Minimum risk score (0–100) |
| `indicator_type` | `all` | Filter: `ipv4`, `ipv6`, `domain`, `hash`, `phone`, `email`, or `all` |

This is a **GET** download (no CSRF) so the dashboard can link directly. Rate-limited. On a public VPS, restrict via reverse proxy if needed; homelab localhost use is fine.

Links appear on the Search tab and in bulk result views.

### AI summaries

Ollama returns **2 sentences** plus **3 `ACTION:` bullets** with suggested next steps for pentesters. Cached 1 hour per indicator/file fingerprint.

### Next steps panel

For **MALICIOUS**, **SUSPICIOUS**, and **UNKNOWN** results, the report includes a **Next steps (manual lab)** block:

- Copy hashes or IOC value
- Copy on-disk sample path (`data/samples/...`)
- Suggested CLI commands (display only — never executed by the app)

**File uploads:** the expandable RE workflow uses a **static baseline** per file type (exe, apk, pdf, zip, office). When **Ollama** is running, steps are **tailored to that sample** (YARA hits, permissions, embedded IOCs). If Ollama is unavailable, the generic workflow is shown instead.

### Copy full report

On **file**, **indicator**, and **bulk** result views, use **Copy full report** to copy a structured plain-text summary (same sections as the web UI) for tickets or notes. Bulk paste and file import results both include this button.

---

## File analysis (static + YARA + optional MobSF)

Upload on the **File** tab. Supported types:

| Type | Extensions | Notes |
|------|------------|-------|
| PE | `.exe` | Entropy, imports, strings |
| APK | `.apk` | Permissions, DEX; use **androguard** for full manifest |
| Archive | `.zip` | **Listing only** — no extract or execute in the web app |
| PDF | `.pdf` | Byte scan; optional `pdfid` |
| Office | `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptm` | Optional `oletools` for macros |

All uploads also run **YARA** against rules in `data/yara_rules/`.

| Layer | Where it runs | EXE | APK |
|-------|---------------|-----|-----|
| **Static** | Web app (parse-only, never executed) | PE entropy, imports, strings | Permissions, DEX, native libs |
| **YARA** | Web app (`services/yara_scan.py`) | All uploaded bytes | All uploaded bytes |
| **Dynamic** (opt-in) | `scripts/sandbox_worker.py` | Mock only in `auto` mode* | MobSF Docker or mock |

\* **Homelab default:** use static + YARA for `.exe`. Full EXE detonation requires **CAPE** on a KVM host (`SANDBOX_BACKEND=cape`) — see optional lab section below.

- Samples stored on disk by SHA256: `data/samples/<prefix>/<sha256>` (not in SQLite)
- Metadata in `file_samples` table; hashes cross-checked against MalwareBazaar / local DB
- Max upload: 32 MB (`MAX_UPLOAD_BYTES`)
- UI shows YARA rule names, static metadata (package, permissions, embedded URLs/IPs), and finding badges (`signature`, `intel`, `heuristic`)

### File verdicts

Files use score bands similar to indicators, with an explicit **UNKNOWN** when there is no useful signal:

| Verdict | Meaning |
|---------|---------|
| **MALICIOUS** | Risk score ≥ 70 |
| **SUSPICIOUS** | Risk score ≥ 20 |
| **CLEAN** | In local hash feeds with low score, or low-signal YARA only |
| **UNKNOWN** | Not in local hash feeds **and** zero YARA matches — **not** confirmation of safety |

Use the **Next steps** panel to copy paths into Ghidra, `strings`, or your VM tooling.

### Androguard (recommended for APK uploads)

Without **androguard**, APK analysis uses a basic ZIP/byte scan (permissions guessed from raw strings, no real manifest parse). Install it in your venv for homelab-quality APK reports:

```bash
source venv/bin/activate
pip install androguard
```

After install, uploads expose **package name**, **app label**, **SDK versions**, and a full **permission list** in the file report. Verify with `./scripts/check-deps.sh` (should show `androguard OK`).

### YARA rules

Rules live on disk under `data/yara_rules/` (never in SQLite). Bootstrap rules ship in `yara_rules/bootstrap/` for offline dev.

```bash
# Install system YARA (Arch)
sudo pacman -S yara
pip install -r requirements.txt

# Optional: download community rule bundle (conditional sync)
python ingest_yara_rules.py
python ingest_yara_rules.py --force   # re-download
```

Configure `YARA_RULES_DIR` and `YARA_RULES_BUNDLE_URL` in `.env` if needed.

### Dynamic sandbox (homelab — MobSF for APK)

Recommended `.env` for a single homelab box:

```bash
SANDBOX_BACKEND=auto   # MobSF for .apk when reachable; mock otherwise
```

```bash
# Terminal 1 — web app
./scripts/dev.sh

# Terminal 2 — MobSF
docker compose --profile mobsf up

# Terminal 3 — worker
python scripts/sandbox_worker.py
```

Enable **Run APK dynamic analysis** when uploading an `.apk`. The UI polls `GET /api/analysis-job/{id}` until complete.

**Dev without Docker:** `SANDBOX_BACKEND=mock` — simulated dynamic results for testing.

**Custom automation:** `SANDBOX_BACKEND=script` with `SANDBOX_SCRIPT` — see [custom-sandbox.md](../dev/custom-sandbox.md).

### Optional: CAPE lab (EXE detonation)

CAPE requires nested KVM and is **not** part of the default homelab path:

```bash
./scripts/sandbox-setup-cape.sh
docker compose --profile cape up
# SANDBOX_BACKEND=cape
```

**Public VPS:** do not expose MobSF/CAPE ports — see [ops/deployment.md](../ops/deployment.md).

---

## API endpoints

All lookup endpoints return **HTML partials** for HTMX (not JSON).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard |
| `GET` | `/health` | Health check (JSON) |
| `POST` | `/api/lookup` | Indicator lookup (IPv4, IPv6, domain, hash, phone, email) |
| `POST` | `/api/bulk-lookup` | Bulk IOC paste (max 50 lines) |
| `GET` | `/api/export/blocklist.csv` | CSV export for lab blocklists |
| `POST` | `/api/lab-scan` | Opt-in nmap/ping job (requires `LAB_SCAN_ENABLED=1`) |
| `GET` | `/api/scan-job/{id}` | Lab scan status / merged result (HTMX poll) |
| `GET` | `/api/history` | Recent lookup history (HTMX fragment) |
| `POST` | `/api/analyze-file` | File analysis; optional `run_dynamic=1` |
| `GET` | `/api/analysis-job/{id}` | Dynamic job status / merged result (HTMX poll) |
| `POST` | `/api/ip` | Legacy IPv4-only lookup |
| `POST` | `/api/intel-search` | FTS search over collected intel (requires `THREATSCOPE_ADMIN=1`) |

Form fields: `q`, `indicator_type` (`auto`|`ipv4`|`ipv6`|`domain`|`hash`|`phone`|`email`), `csrf_token`.

Intel search: `q`, `csrf_token` (admin only).

Lookups include passive enrichment when GeoLite2 databases are present (`data/geoip/`): country/ASN for IPs, DNS resolution for domains and email domains, and threat-actor hints from feed tags. Phone lookups can optionally call an external API when `PHONE_LOOKUP_ENABLED=1` (sends the number to a third party). Email lookups run local domain DNS/MX checks by default; `EMAIL_LOOKUP_ENABLED=1` optionally queries a third-party email reputation API (sends the full address).

Lab scan (`POST /api/lab-scan`): form fields `target`, `type` (`ipv4`|`ipv6`|`domain`), `csrf_token`. Requires `LAB_SCAN_ENABLED=1` and `python scripts/scan_worker.py` running separately. Never auto-scans on lookup — user must click **Run lab scan**.

Bulk lookup: `iocs`, `csrf_token`.

File upload: `file`, `csrf_token`, optional `run_dynamic=1`.
