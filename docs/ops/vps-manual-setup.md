# VPS manual setup (SSH on server)

Use this when you are already logged in as **root** on the VPS and have cloned the repo (for example `~/threadscope`). Automated remote deploy from your laptop is in [deployment.md](deployment.md); this page is copy-paste for an active SSH session.

**Do not run `ingest_samples.py` on the VPS** — sample hash ingest stays on the lab tier. See [../dev/sample-hash-ingest.md](../dev/sample-hash-ingest.md) and [../dev/architecture-two-tier.md](../dev/architecture-two-tier.md).

---

## 1. Pull latest code

If you cloned to root’s home:

```bash
cd ~/threadscope
git pull origin main
```

For a fresh clone instead:

```bash
git clone --branch main https://github.com/kushalimdeutschland-blip/threadscope.git ~/threadscope
cd ~/threadscope
```

Optional production path (matches systemd/nginx defaults in docs):

```bash
git clone --branch main https://github.com/kushalimdeutschland-blip/threadscope.git /opt/threatscope
```

---

## 2. One-shot bootstrap

From the repo root on the VPS:

```bash
chmod +x scripts/vps-bootstrap.sh
bash scripts/vps-bootstrap.sh
```

Defaults: `REPO_DIR=$HOME/threadscope`, public HTTP on `167.233.16.244`.

Custom paths:

```bash
REPO_DIR=/opt/threatscope bash scripts/vps-bootstrap.sh
```

Set admin password hash (bcrypt) before bootstrap:

```bash
export BOOTSTRAP_ADMIN_HASH="$(python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR-STRONG-PASSWORD', bcrypt.gensalt()).decode())")"
cd ~/threadscope && bash scripts/vps-bootstrap.sh
```

The script will:

- Install apt packages (git, python3, nginx, curl, …) and Ollama + `qwen2.5:1.5b`
- Create `threatscope` system user and `chown` the repo
- Create `.env` from `.env.production.example` (`THREATSCOPE_PUBLIC=1`, `SANDBOX_BACKEND=off`, …)
- Create venv, `pip install -r requirements.txt`
- Stop `threatscope`, run `ingest_feeds.py`, install systemd + nginx, enable services
- `curl` local `/health`

First feed ingest can take several minutes.

---

## 3. Verify

```bash
curl -sf http://127.0.0.1:8000/health
curl -sI http://167.233.16.244/ | head -5
systemctl status threatscope nginx ollama --no-pager
```

In a browser: `http://167.233.16.244/` — Search/File tabs for visitors; **Intel** after `http://167.233.16.244/admin/login`.

---

## 4. After lab sample hash ingest (optional)

On the **lab** machine only:

```bash
./scripts/ingest-sample-hashes.sh
```

Sync SQLite to the VPS (from lab):

```bash
# On VPS first:
ssh root@167.233.16.244 'systemctl stop threatscope'

# On lab:
VPS_HOST=167.233.16.244 ./scripts/sync-hash-db-to-production.sh

# On VPS:
ssh root@167.233.16.244 'chown threatscope:threatscope /opt/threatscope/data/threatscope.db && systemctl start threatscope'
```

If the app lives in `~/threadscope`, set `REMOTE_DIR=~/threadscope/data` when running the sync script.

---

## 5. Updates (routine)

```bash
cd ~/threadscope   # or /opt/threatscope
git pull origin main
sudo -u threatscope ./venv/bin/pip install -q -r requirements.txt
systemctl stop threatscope
sudo -u threatscope ./venv/bin/python ingest_feeds.py --if-changed
systemctl start threatscope
systemctl reload nginx
```

---

## 6. Security reminders

| Item | Action |
|------|--------|
| Ollama | Must listen on `127.0.0.1:11434` only — never expose 11434 publicly |
| App | `127.0.0.1:8000` behind nginx |
| Firewall | Allow 80 (and 443 when you add TLS); block 8000 and 11434 from WAN |
| Secrets | Never commit `.env`; set `ADMIN_PASSWORD_HASH` on the server |
| Dynamic sandbox | Off on public VPS (`SANDBOX_BACKEND=off`); lab uses `batch_sandbox_ingest.py` |

---

## Related

- [deployment.md](deployment.md) — full checklist, TLS, cron
- [../dev/architecture-two-tier.md](../dev/architecture-two-tier.md) — lab vs public split
- `scripts/deploy-vps-from-github.sh` — deploy from your workstation via SSH
