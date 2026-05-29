# VPS Deployment & Security Guide

ThreatScope is designed to be exposed publicly (portfolio site, free security tool). Follow this checklist before going live.

---

## Architecture

```
Internet
    │
    ▼
Nginx/Caddy (TLS, rate limit, body size limit)
    │
    ▼
ThreatScope (127.0.0.1:8000)
    ├── SQLite (data/threatscope.db)
    └── Ollama (127.0.0.1:11434 ONLY)

Cron (daily)
    └── ingest_feeds.py → refreshes SQLite from OSINT feeds
```

**Never expose Ollama (port 11434) to the internet.** It has no authentication.

---

## Public personal site

Use when exposing ThreatScope on the internet without visitor accounts. Copy [`.env.production.example`](../../.env.production.example) to `.env` and run [`scripts/predeploy-check.sh`](../../scripts/predeploy-check.sh) before going live.

| Setting | Purpose |
|---------|---------|
| `THREATSCOPE_PUBLIC=1` | Stricter rate limits for visitors; signed-in admin is exempt from those limits; no lookup history for visitors; static + YARA uploads only |
| `TRUST_PROXY_HEADERS=1` | Per-visitor slowapi limits behind Nginx (default when `ENV=production`) |
| `ADMIN_PASSWORD_HASH` | Operator login at `/admin` for Intel tab + feed accuracy |
| `THREATSCOPE_ADMIN=0` | Do not enable env admin on the public internet |

**Uvicorn** (see [`deploy/systemd/threatscope.service`](../../deploy/systemd/threatscope.service)):

```bash
uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1
```

**Nginx** example: [`deploy/nginx/threatscope.conf`](../../deploy/nginx/threatscope.conf)

Trust pages: `GET /about`, `GET /privacy`. Footer links and expanded feed attribution are on the main UI.

**Admin on a public host:** visitors use Search/File only. After `POST /admin/login`, the same browser session sees the **Intel** tab and can open `/api/feed-accuracy`.

---

## Pre-deploy checklist

- [ ] Run `./scripts/predeploy-check.sh`
- [ ] Set `ENV=production` in `.env`
- [ ] Generate and set `SECRET_KEY`:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(48))"
  ```
- [ ] Set `ALLOWED_HOSTS` to your domain(s) only
- [ ] Bind app to `127.0.0.1` — put Nginx/Caddy in front for TLS
- [ ] Firewall: allow 80/443 only; block 8000 and 11434 from public
- [ ] Ollama listens on `127.0.0.1:11434` only
- [ ] Persist `data/threatscope.db` on a volume
- [ ] Run initial feed ingest: `python ingest_feeds.py`
- [ ] Schedule daily `ingest_feeds.py` cron
- [ ] Add feed attribution to footer if public-facing
- [ ] Verify `/docs` is disabled (automatic when `ENV=production`)

See also [user/configuration.md](../user/configuration.md) for all env vars.

---

## Environment variables (production)

Homelab (private):

```bash
ENV=production
SECRET_KEY=<48+ char random string>
ALLOWED_HOSTS=threatscope.yourdomain.com
RATE_LIMIT=30/minute
FILE_UPLOAD_RATE_LIMIT=10/hour
ADMIN_PASSWORD_HASH=<bcrypt>
TRUST_PROXY_HEADERS=1
```

Public personal site — see [`.env.production.example`](../../.env.production.example) (`THREATSCOPE_PUBLIC=1`, `PUBLIC_*` limits, `SANDBOX_BACKEND=off`).

---

## Nginx reverse proxy

Increase `client_max_body_size` if you enable file uploads (default app limit: 32 MB):

```nginx
server {
    listen 443 ssl http2;
    server_name threatscope.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/threatscope.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/threatscope.yourdomain.com/privkey.pem;

    # Indicator lookups: 4k is enough. File uploads: match MAX_UPLOAD_BYTES.
    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;   # Ollama summaries can be slow on first request
    }
}
```

---

## Systemd service

```ini
[Unit]
Description=ThreatScope
After=network.target ollama.service
Requires=ollama.service

[Service]
User=threatscope
WorkingDirectory=/opt/threatscope
EnvironmentFile=/opt/threatscope/.env
ExecStart=/opt/threatscope/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Copy the full unit from [`deploy/systemd/threatscope.service`](../../deploy/systemd/threatscope.service).

---

## OSINT feed ingest (cron)

Run **outside** the web app process. Refreshes 500k+ indicators from 10+ OSINT feeds.

```bash
# Manual — full refresh
/opt/threatscope/venv/bin/python /opt/threatscope/ingest_feeds.py --force

# Skip unchanged feeds (after first full ingest)
/opt/threatscope/venv/bin/python /opt/threatscope/ingest_feeds.py --if-changed

# Wrapper (forwards flags)
/opt/threatscope/scripts/ingest-feeds.sh --if-changed
```

Optional ThreatFox ingest: set `ABUSE_CH_AUTH_KEY` in the service environment (free key at [auth.abuse.ch](https://auth.abuse.ch/)).

### Cron

```cron
# Daily full ingest at 04:00 UTC
0 4 * * * /opt/threatscope/scripts/ingest-feeds.sh --force >> /var/log/threatscope-ingest.log 2>&1

# Every 6 hours — conditional sync
0 */6 * * * /opt/threatscope/scripts/ingest-feeds.sh --if-changed >> /var/log/threatscope-ingest.log 2>&1
```

Ensure `data/threatscope.db` is on persistent storage before enabling cron.

### Feed attribution

ThreatScope uses free feeds from:

- [abuse.ch](https://abuse.ch) — URLhaus, Feodo Tracker, MalwareBazaar; ThreatFox (optional)
- [Blocklist.de](https://www.blocklist.de/)
- [CINSscore](https://cinsscore.com/)
- [Spamhaus DROP](https://www.spamhaus.org/drop/)
- [OpenPhish](https://openphish.com/)
- [FireHOL](https://github.com/firehol/blocklist-ipsets)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database)

Review [abuse.ch Terms of Use](https://urlhaus.abuse.ch/api/) and [Spamhaus DROP terms](https://www.spamhaus.org/drop/) before public deployment.

Recommended footer credit:

> Threat intelligence data courtesy of [abuse.ch](https://abuse.ch), [Blocklist.de](https://www.blocklist.de/), [CINSscore](https://cinsscore.com/), and [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database)

---

## Ollama setup

```bash
# Install and enable
sudo systemctl enable --now ollama

# Pull model once
ollama pull qwen2.5:1.5b

# Verify localhost-only binding
ss -tlnp | grep 11434
# Expected: 127.0.0.1:11434 — NOT 0.0.0.0:11434
```

**CachyOS / Arch (local dev):**

```bash
sudo pacman -S ollama
sudo systemctl enable --now ollama
ollama pull qwen2.5:1.5b
```

---

## Security controls

| Threat | Mitigation |
|--------|------------|
| CSRF | Double-submit cookie on all POST endpoints |
| Rate limit abuse | slowapi per IP + Nginx limits |
| SQL injection | Parameterized queries only |
| XSS | Jinja2 auto-escape + CSP headers |
| SSRF (Ollama) | URL validated to localhost only |
| Host header poisoning | TrustedHostMiddleware (production) |
| Log leakage | Lookups use POST, not GET query strings |
| Malicious file upload | Magic-byte check, size cap; web app parse-only (never execute) |
| Dynamic sandbox escape | Run MobSF/CAPE on private host only; never expose ports 8001/8002 publicly |
| Zip bomb (APK) | Uncompressed size limit in parser |
| Info disclosure | Generic errors; `/docs` off in production |
| Feed download SSRF | Hardcoded HTTPS URLs in ingest script |

---

## What attackers will try

- **Rate limit abuse** — slowapi + Nginx
- **CSRF on lookup forms** — token validation
- **Malware upload to trigger execution** — web app parses only; dynamic runs in isolated worker/sandbox
- **Public MobSF/CAPE exposure** — bind sandboxes to 127.0.0.1 on a lab machine, not the portfolio VPS
- **SQL injection in search** — parameterized queries + strict validation
- **Scanning `/docs`, `/openapi.json`** — disabled in production
- **Ollama port scanning** — firewall block on 11434

Keep dependencies updated:

```bash
pip install -U -r requirements.txt
```

---

## Initial deployment sequence

```bash
# 1. Clone and install
git clone <repo> /opt/threatscope
cd /opt/threatscope
python -m venv venv && ./venv/bin/pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env — set ENV=production, SECRET_KEY, ALLOWED_HOSTS

# 3. Populate database
./venv/bin/python ingest_feeds.py

# 4. Start services
sudo systemctl enable --now ollama
sudo systemctl enable --now threatscope   # after creating systemd unit

# 5. Verify
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:11434/
```
