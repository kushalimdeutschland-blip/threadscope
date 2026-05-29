# Quick Start

## Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) on port `11434`
- **YARA** (system library + `yara-python` from `requirements.txt`)

**Recommended (no sudo):** project-local Ollama in `.local/bin/` (gitignored, ~3 GB with GPU libs):

```bash
# If .local/bin/bin/ollama is missing:
./scripts/install-ollama-local.sh

./scripts/start-ollama.sh              # terminal 1
.local/bin/bin/ollama pull qwen2.5:1.5b   # once, while serve is running
```

**CachyOS / Arch (system-wide, optional):**

```bash
sudo pacman -S ollama yara
sudo systemctl enable --now ollama
ollama pull qwen2.5:1.5b
```

ThreatScope only needs an API on `http://127.0.0.1:11434` — use either local or system Ollama, not both at once.

---

## Install and run

```bash
cd threatscope
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Recommended for APK static analysis (package, permissions, SDK)
pip install androguard

# Populate database with live OSINT feeds (100k+ indicators)
python ingest_feeds.py

# YARA rules (optional full bundle; bootstrap rules ship in-repo)
python ingest_yara_rules.py

# Optional: add dev sample data on top
python seed_db.py

# Start services (two terminals)
./scripts/start-ollama.sh    # Terminal 1
./scripts/dev.sh             # Terminal 2 → http://127.0.0.1:8000
```

> Always use the venv Python: `./venv/bin/python ingest_feeds.py` if not activated.

---

## Pentester lab VM checklist

Run this after install on a dedicated lab machine (not your daily driver):

```bash
./scripts/check-deps.sh
```

| Step | Command / action | Purpose |
|------|------------------|---------|
| System YARA | `sudo pacman -S yara` | `yara-python` + rules compile |
| Ollama | `sudo pacman -S ollama` → `ollama pull qwen2.5:1.5b` | AI analyst summaries |
| APK depth | `pip install androguard` | Real manifest/permissions in file reports |
| Office/PDF | `pip install oletools pdfid` (optional) | Macro and PDF static analysis |
| Intel DB | `python ingest_feeds.py` | OSINT lookups |
| Phone scam list | Edit `data/feeds/phone_scam.csv` → ingest | Local phone IOCs |
| Email scam list | Edit `data/feeds/email_scam.csv` → ingest | Local email IOCs |
| GeoIP (optional) | MaxMind GeoLite2 → `data/geoip/*.mmdb` | Country/ASN on IP/domain lookups |
| YARA rules | `python ingest_yara_rules.py` | File signature scan |
| Cron | `ingest-feeds.sh --if-changed` every 6h | Keep feeds fresh |
| Intel (optional) | `INTEL_COLLECTION_ENABLED=1` + `ingest_intel.py` or `intel_worker.py` | RSS/paste/leak narratives + IOC extract; see [intel-collection](../dev/intel-collection.md) |
| MobSF (optional) | `docker compose --profile mobsf up` | APK dynamic detonation |
| Worker | `python scripts/sandbox_worker.py` | Processes dynamic jobs |
| Lab scan (optional) | `LAB_SCAN_ENABLED=1` + `python scripts/scan_worker.py` | Opt-in nmap/ping from homelab |
| Custom automation | [Custom sandbox](../dev/custom-sandbox.md) | `SANDBOX_BACKEND=script` + your script |

**Daily workflow:** Search tab for IPs/domains/hashes/phones/emails (or **Bulk IOC** paste) → File tab for samples before running them → use **Next steps** panel to copy paths into Ghidra/strings on the same VM.

### Optional: phone/email lookup, GeoIP, lab scan

```bash
# Phone scam CSV (local only) — edit data/feeds/phone_scam.csv then:
python ingest_feeds.py --feed phone_scam

# Email scam CSV (local only) — edit data/feeds/email_scam.csv then:
python ingest_feeds.py --feed email_scam

# Passive GeoIP — download GeoLite2-Country + GeoLite2-ASN from MaxMind into:
#   data/geoip/GeoLite2-Country.mmdb
#   data/geoip/GeoLite2-ASN.mmdb

# Optional external phone API (sends number to third party):
#   PHONE_LOOKUP_ENABLED=1 PHONE_LOOKUP_API_KEY=... PHONE_LOOKUP_PROVIDER=numverify

# Optional external email API (sends address to third party, e.g. emailrep.io):
#   EMAIL_LOOKUP_ENABLED=1 EMAIL_LOOKUP_API_KEY=... EMAIL_LOOKUP_PROVIDER=emailrep
# Local MX/DNS for the email domain works without these; optional: pip install dnspython

# Opt-in active scan (separate worker, off by default):
#   LAB_SCAN_ENABLED=1 in .env (or export) for the web app AND worker:
#   LAB_SCAN_ENABLED=1 ./scripts/dev.sh
#   LAB_SCAN_ENABLED=1 python scripts/scan_worker.py
#   Then look up an IP or domain — **Run lab scan** is in the results panel, not on the search form.
```


## Test lookups

| Tab | Example | Expected |
|-----|---------|----------|
| IPv4 | `162.243.103.246` | MALICIOUS (Feodo C2) |
| IPv4 | `221.15.178.56` | MALICIOUS (URLhaus) |
| Domain | `fksdx.v-vill.hu` | MALICIOUS (URLhaus) |
| Phone | `+1 800-555-1234` | Depends on `data/feeds/phone_scam.csv` |
| Email | `phishing@evil.example` | Depends on `data/feeds/email_scam.csv` |
| Hash | `44d88612fea8a8f36de82e1278abb02f` | MALICIOUS (if seeded) |
| File | Upload `.exe`, `.apk`, `.zip`, `.pdf`, or Office | Static + YARA report |
| Bulk | Search tab → Bulk IOC lookup | Table of verdicts (max 50) |

---

## Helper scripts

| Script | Purpose |
|--------|---------|
| `scripts/dev.sh` | Start FastAPI with auto-reload |
| `scripts/start-ollama.sh` | Start Ollama bound to localhost |
| `scripts/ingest-feeds.sh` | Cron-friendly feed ingest wrapper |
| `ingest_intel.py` | Intel collection (RSS, paste, leak APIs — requires `INTEL_COLLECTION_ENABLED=1`) |
| `scripts/ingest-intel.sh` | Cron-friendly intel ingest wrapper |
| `scripts/intel_worker.py` | Optional daemon for periodic intel collection |
| `ingest_yara_rules.py` | Sync YARA rules bundle (`--force` to re-download) |
| `scripts/sandbox_worker.py` | Process MobSF/mock dynamic jobs |
| `scripts/scan_worker.py` | Process opt-in lab nmap/ping jobs |

---

## Next steps

- [Configuration](configuration.md) — environment variables
- [Feeds & analysis](feeds-and-analysis.md) — ingest details, file uploads, API
- [Deployment](../ops/deployment.md) — production VPS setup
