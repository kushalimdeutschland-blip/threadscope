#!/usr/bin/env bash
# ThreatScope VPS bootstrap — run ON THE SERVER as root (SSH session).
#
# Clones or uses an existing git checkout, installs deps, configures production
# .env, runs feed ingest, and enables systemd + nginx (HTTP on VPS IP).
#
# Does NOT run ingest_samples.py (lab-only).
#
# Usage (on VPS as root, from repo root or after clone):
#   cd /opt/threatscope && bash scripts/vps-bootstrap.sh
#
# Environment (export or prefix on the same line):
#   REPO_DIR          Install path (default: /opt/threatscope)
#   VPS_IP            Public IP for ALLOWED_HOSTS / nginx (default: 167.233.16.244)
#   BOOTSTRAP_ADMIN_HASH  bcrypt for ADMIN_PASSWORD_HASH (recommended)
#   THREATSCOPE_REPO_URL  Git remote (default: project GitHub)
#   THREATSCOPE_BRANCH    Branch to clone/pull (default: main)
#
#   BOOTSTRAP_ADMIN_HASH='$2b$12$...' bash scripts/vps-bootstrap.sh
#
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

VPS_IP="${VPS_IP:-167.233.16.244}"
REPO_URL="${THREATSCOPE_REPO_URL:-https://github.com/kushalimdeutschland-blip/threadscope.git}"
BRANCH="${THREATSCOPE_BRANCH:-main}"
ADMIN_HASH="${BOOTSTRAP_ADMIN_HASH:-${ADMIN_PASSWORD_HASH:-}}"

REPO_DIR="${REPO_DIR:-/opt/threatscope}"
REPO_DIR="${REPO_DIR/#\~/$HOME}"

if [[ ! -d "$REPO_DIR" ]]; then
  echo "=== Git clone -> $REPO_DIR ==="
  mkdir -p "$(dirname "$REPO_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$REPO_DIR"
fi
REPO_DIR="$(cd "$REPO_DIR" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (or: sudo bash $0)" >&2
  exit 1
fi

echo "=== [1/10] System packages ==="
apt-get update -qq
PACKAGES="git python3 python3-venv python3-pip nginx curl build-essential openssl"
apt-get install -y -qq $PACKAGES
apt-get install -y -qq yara 2>/dev/null || apt-get install -y -qq libyara-dev yara 2>/dev/null || true

echo "=== [2/10] Ollama ==="
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
systemctl enable ollama 2>/dev/null || true
systemctl start ollama 2>/dev/null || true
sleep 2
ollama pull qwen2.5:1.5b || true

echo "=== [3/10] User threatscope ==="
if ! id threatscope >/dev/null 2>&1; then
  useradd -r -m -s /bin/bash threatscope
fi
chown -R threatscope:threatscope "$REPO_DIR"

echo "=== [4/10] Git pull (latest main) ==="
sudo -u threatscope git -C "$REPO_DIR" fetch origin "$BRANCH"
sudo -u threatscope git -C "$REPO_DIR" checkout "$BRANCH"
sudo -u threatscope git -C "$REPO_DIR" pull origin "$BRANCH" || true

echo "=== [5/10] .env ==="
SECRET_KEY="$(openssl rand -hex 32)"
if [[ ! -f "$REPO_DIR/.env" ]]; then
  cp "$REPO_DIR/.env.production.example" "$REPO_DIR/.env"
fi
export SECRET_KEY ADMIN_HASH REPO_DIR VPS_IP
python3 <<'PYENV'
import os
import re
from pathlib import Path

p = Path(os.environ["REPO_DIR"]) / ".env"
text = p.read_text(encoding="utf-8")
updates = {
    "ENV": "production",
    "THREATSCOPE_PUBLIC": "1",
    "ALLOWED_HOSTS": f"{os.environ['VPS_IP']},localhost,127.0.0.1",
    "TRUST_PROXY_HEADERS": "1",
    "SECRET_KEY": os.environ["SECRET_KEY"],
    "THREATSCOPE_ADMIN": "0",
    "INTEL_COLLECTION_ENABLED": "0",
    "LAB_SCAN_ENABLED": "0",
    "SANDBOX_BACKEND": "off",
    "HOST": "127.0.0.1",
    "PORT": "8000",
}
admin = os.environ.get("ADMIN_HASH", "").strip()
if admin:
    updates["ADMIN_PASSWORD_HASH"] = admin
lines = text.splitlines()
out: list[str] = []
seen: set[str] = set()
for line in lines:
    m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
    if m and m.group(1) in updates:
        k = m.group(1)
        out.append(f"{k}={updates[k]}")
        seen.add(k)
    else:
        out.append(line)
for k, v in updates.items():
    if k not in seen:
        out.append(f"{k}={v}")
p.write_text("\n".join(out) + "\n", encoding="utf-8")
PYENV
chown threatscope:threatscope "$REPO_DIR/.env"
chmod 600 "$REPO_DIR/.env"

echo "=== [6/10] Python venv + requirements ==="
if [[ ! -d "$REPO_DIR/venv" ]]; then
  sudo -u threatscope python3 -m venv "$REPO_DIR/venv"
fi
sudo -u threatscope "$REPO_DIR/venv/bin/pip" install -q -U pip wheel
sudo -u threatscope "$REPO_DIR/venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"

mkdir -p "$REPO_DIR/data"
chown -R threatscope:threatscope "$REPO_DIR/data"

echo "=== [7/10] Feed ingest (service stopped) ==="
systemctl stop threatscope 2>/dev/null || true
if ! sudo -u threatscope "$REPO_DIR/venv/bin/python" "$REPO_DIR/ingest_feeds.py"; then
  echo "WARNING: ingest_feeds.py exited non-zero (e.g. CISA 403). Other feeds may have loaded; continuing bootstrap."
fi

echo "=== [8/10] systemd + nginx ==="
sed "s|/opt/threatscope|$REPO_DIR|g" "$REPO_DIR/deploy/systemd/threatscope.service" \
  > /etc/systemd/system/threatscope.service
sed "s|/opt/threatscope|$REPO_DIR|g; s|167.233.16.244|$VPS_IP|g" \
  "$REPO_DIR/deploy/nginx/threatscope-ip.conf" \
  > /etc/nginx/sites-available/threatscope
ln -sf /etc/nginx/sites-available/threatscope /etc/nginx/sites-enabled/threatscope
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
nginx -t

echo "=== [9/10] Enable services ==="
systemctl daemon-reload
systemctl enable threatscope nginx ollama
systemctl restart ollama || true
systemctl restart threatscope
systemctl restart nginx

echo "=== [10/10] Health check ==="
sleep 3
curl -sf "http://127.0.0.1:8000/health" || {
  journalctl -u threatscope -n 40 --no-pager
  exit 1
}
echo ""
echo "Bootstrap OK."
echo "  App (local):  http://127.0.0.1:8000/"
echo "  Public HTTP:  http://${VPS_IP}/"
echo "  Admin login:  http://${VPS_IP}/admin/login"
if [[ -z "$ADMIN_HASH" ]]; then
  echo ""
  echo "Set admin password hash and re-run step 5 or edit ${REPO_DIR}/.env:"
  echo "  BOOTSTRAP_ADMIN_HASH=\$(python3 -c \"import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt()).decode())\") \\"
  echo "    bash scripts/vps-bootstrap.sh"
fi
