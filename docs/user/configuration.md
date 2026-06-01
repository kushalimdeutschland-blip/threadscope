# Configuration

Copy [`.env.example`](../../.env.example) to `.env`. Never commit `.env`.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ENV` | `development` | Set to `production` on VPS |
| `SECRET_KEY` | auto (dev) | **Required in production** — CSRF signing |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | Host header allowlist (production) |
| `HOST` | `127.0.0.1` | App bind address |
| `PORT` | `8000` | App port |
| `RATE_LIMIT` | `30/minute` | Per-IP indicator lookup limit |
| `PUBLIC_RATE_LIMIT` | `20/minute` | Lookup limit when `THREATSCOPE_PUBLIC=1` |
| `PUBLIC_FILE_UPLOAD_RATE_LIMIT` | `5/hour` | Upload limit when `THREATSCOPE_PUBLIC=1` |
| `PUBLIC_BLOCKLIST_RATE_LIMIT` | `5/hour` | Blocklist CSV when `THREATSCOPE_PUBLIC=1` |
| `TRUST_PROXY_HEADERS` | on in production | Use `X-Forwarded-For` / `X-Real-IP` for rate limits behind Nginx |
| `THREATSCOPE_PUBLIC` | off | Public site profile: stricter limits, no visitor history, static-only uploads |
| `ADMIN_ALLOW_DYNAMIC` | off | With `THREATSCOPE_PUBLIC=1`: signed-in admin may opt into dynamic sandbox on file upload |
| `FILE_UPLOAD_RATE_LIMIT` | `10/hour` | Per-IP file upload limit |
| `MAX_BODY_BYTES` | `4096` | Max form POST body size |
| `MAX_UPLOAD_BYTES` | `33554432` | Max file upload size (32 MB) |
| `OLLAMA_URL` | `http://127.0.0.1:11434/api/generate` | Local only — never public |
| `OLLAMA_MODEL` | `qwen2.5:1.5b` | Model name |
| `OLLAMA_TIMEOUT` | `120` | LLM request timeout (seconds) |
| `OLLAMA_MAX_CONCURRENT` | `3` | Max parallel Ollama requests |
| `SUMMARY_CACHE_TTL` | `3600` | AI summary cache TTL (seconds) |
| `YARA_RULES_DIR` | `data/yara_rules` | On-disk YARA rules directory |
| `YARA_RULES_BUNDLE_URL` | GitHub zip URL | Community bundle for `ingest_yara_rules.py` |
| `SANDBOX_BACKEND` | `mock` | `mock`, `off`, `mobsf`, `cape`, `script`, or `auto` |
| `SANDBOX_SCRIPT` | _(empty)_ | Path to analyzer script when `SANDBOX_BACKEND=script` |
| `SANDBOX_SCRIPT_PYTHON` | `python3` | Interpreter for `SANDBOX_SCRIPT` |
| `MOBSF_URL` | `http://127.0.0.1:8001` | MobSF base URL (localhost only) |
| `MOBSF_API_KEY` | _(empty)_ | MobSF API key if configured in container |
| `CAPE_URL` | `http://127.0.0.1:8002` | CAPE base URL (localhost only) |
| `CAPE_API_TOKEN` | _(empty)_ | CAPE API token if enabled |
| `SANDBOX_MAX_CONCURRENT` | `1` | Max parallel jobs in worker |
| `SANDBOX_JOB_TIMEOUT` | `600` | Per-job timeout (seconds) |
| `SANDBOX_MOCK_DELAY` | `6` | Simulated scan time for mock backend |
| `SANDBOX_POLL_INTERVAL` | `3` | Worker poll interval (seconds) |
| `SANDBOX_DYNAMIC_RATE_LIMIT` | `5/hour` | Reserved for dynamic job rate limits |
| `INTEL_COLLECTION_ENABLED` | off | Set to `1` to run `ingest_intel.py` / `intel_worker.py` |
| `INTELX_API_KEY` | _(empty)_ | Intelligence X API (paste collector) |
| `PASTEBIN_API_KEY` | _(empty)_ | Pastebin scraping API dev key |
| `DEHASHED_API_KEY` / `DEHASHED_API_EMAIL` | _(empty)_ | Optional DeHashed leak API (IOC-only) |
| `INTEL_WORKER_INTERVAL` | `3600` | `intel_worker.py` sleep between runs (seconds) |
| `INTEL_MAX_BODY_BYTES` | `32768` | Max stored document body per intel item |
| `INTEL_AI_ENABLED` | off | Master gate for local Ollama intel features (sanitized text only) |
| `INTEL_AI_INGEST_SUMMARY` | on | Ingest-time `meta.ai_summary` when master enabled |
| `INTEL_AI_LOOKUP_CONTEXT` | on | Related intel on indicator lookup when master enabled |
| `INTEL_AI_QUERY_EXPAND` | on | FTS query expansion on Intel tab when master enabled |
| `INTEL_AI_MAX_BODY_CHARS` | `4096` | Max chars sent to Ollama for ingest summaries |
| `ADMIN_PASSWORD` | _(empty)_ | Admin login password (never commit; use hash in production) |
| `ADMIN_PASSWORD_HASH` | _(empty)_ | Bcrypt hash for `POST /admin/login` |
| `THREATSCOPE_ADMIN` | off | **Dev only:** Intel tab + feed accuracy without login (`ENV!=production`, not with `THREATSCOPE_PUBLIC`) |

Generate a production secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

If Ollama is unavailable, lookups still work — the AI summary shows a fallback message.

### Custom sandbox script

When `SANDBOX_BACKEND=script`, set `SANDBOX_SCRIPT` to your analyzer (see [custom-sandbox.md](../dev/custom-sandbox.md)) and run `python scripts/sandbox_worker.py` in a separate terminal.

### Intel collection

Separate from public OSINT [`ingest_feeds.py`](../../ingest_feeds.py): narrative documents (RSS, paste APIs, leak APIs) with **IOC-only** storage — passwords and credential pairs are never saved.

1. Set `INTEL_COLLECTION_ENABLED=1` and API keys in `.env` (see `.env.example`).
2. Edit [`data/intel_feeds.yaml`](../../data/intel_feeds.yaml) for RSS URLs and which collectors are enabled.
3. Run out-of-process: `python ingest_intel.py` or `./scripts/ingest-intel.sh --if-changed` (cron), or `python scripts/intel_worker.py` for a daemon.
4. **Admin access:** sign in at `/admin/login` (set `ADMIN_PASSWORD` or `ADMIN_PASSWORD_HASH`), or on a private homelab dev instance set `THREATSCOPE_ADMIN=1`. Then use the **Intel** tab (`POST /api/intel-search`) and **Search** for extracted IOCs.

Generate a bcrypt hash:

```bash
python -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())"
```

Details: [intel-collection.md](../dev/intel-collection.md)

---

## Security controls

Built for public exposure (portfolio / free tool):

| Control | Detail |
|---------|--------|
| POST + CSRF | Indicators not logged in query strings |
| Rate limiting | Per client IP (lookups + uploads); signed-in admin is exempt from visitor limits (`POST /admin/login` stays capped at 5/minute) |
| Strict validation | IPv4/IPv6/domain/hash via `ipaddress` + regex |
| Parameterized SQL | All DB access via `database.py` |
| Ollama SSRF guard | URL locked to localhost |
| Security headers | CSP, X-Frame-Options, HSTS (production) |
| File upload | Magic-byte validation, size caps, parse-only (never execute) |
| Blocklist export | `GET /api/export/blocklist.csv` is unauthenticated (rate-limited); restrict on public VPS via reverse proxy |
| No `/docs` in production | OpenAPI disabled when `ENV=production` |

Full VPS checklist: [ops/deployment.md](../ops/deployment.md)
