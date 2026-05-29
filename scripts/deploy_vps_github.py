#!/usr/bin/env python3
"""Remote VPS deploy via SSH (paramiko). No secrets in this file."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SITE_PACKAGES = REPO_ROOT / "venv/lib/python3.14/site-packages"
if SITE_PACKAGES.is_dir():
    sys.path.insert(0, str(SITE_PACKAGES))

import paramiko  # noqa: E402

DEFAULT_HOST = os.environ.get("VPS_HOST", "167.233.16.244")
DEFAULT_USER = os.environ.get("VPS_USER", "root")
REPO_URL = os.environ.get(
    "THREATSCOPE_REPO_URL",
    "https://github.com/kushalimdeutschland-blip/threadscope.git",
)
BRANCH = os.environ.get("THREATSCOPE_BRANCH", "main")
APP_DIR = "/opt/threatscope"


def read_admin_hash_from_local_env() -> str:
    env_path = Path(os.environ.get("LOCAL_ENV", REPO_ROOT / ".env"))
    if not env_path.is_file():
        return ""
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("ADMIN_PASSWORD_HASH=") and len(line) > len(
            "ADMIN_PASSWORD_HASH="
        ):
            return line.split("=", 1)[1].strip()
    return ""


def build_remote_script(admin_hash: str, allowed_hosts: str) -> str:
    admin_hash_escaped = admin_hash.replace("'", "'\"'\"'")
    return f"""#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

echo "=== [1/10] System packages ==="
apt-get update -qq
PACKAGES="git python3 python3-venv python3-pip nginx curl build-essential"
apt-get install -y -qq $PACKAGES || true
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

echo "=== [4/10] Git clone/pull ==="
if [ -d {APP_DIR}/.git ]; then
  sudo -u threatscope git -C {APP_DIR} fetch origin {BRANCH}
  sudo -u threatscope git -C {APP_DIR} checkout {BRANCH}
  sudo -u threatscope git -C {APP_DIR} pull origin {BRANCH}
  GIT_STATUS=pull
else
  mkdir -p $(dirname {APP_DIR})
  if [ -d {APP_DIR} ] && [ ! -d {APP_DIR}/.git ]; then
    mv {APP_DIR} {APP_DIR}.bak.$(date +%s) || rm -rf {APP_DIR}
  fi
  git clone --branch {BRANCH} {REPO_URL} {APP_DIR}
  chown -R threatscope:threatscope {APP_DIR}
  GIT_STATUS=clone
fi
echo "GIT_RESULT=$GIT_STATUS"

echo "=== [5/10] .env ==="
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_HASH='{admin_hash_escaped}'
if [ ! -f {APP_DIR}/.env ]; then
  cp {APP_DIR}/.env.production.example {APP_DIR}/.env
fi
export SECRET_KEY ADMIN_HASH
python3 << PYENV
import os
import re
from pathlib import Path
p = Path("{APP_DIR}/.env")
text = p.read_text(encoding="utf-8")
updates = {{
    "ENV": "production",
    "THREATSCOPE_PUBLIC": "1",
    "ALLOWED_HOSTS": "{allowed_hosts}",
    "TRUST_PROXY_HEADERS": "1",
    "SECRET_KEY": os.environ["SECRET_KEY"],
    "THREATSCOPE_ADMIN": "0",
    "INTEL_COLLECTION_ENABLED": "0",
    "LAB_SCAN_ENABLED": "0",
    "SANDBOX_BACKEND": "off",
    "HOST": "127.0.0.1",
    "PORT": "8000",
}}
admin = os.environ.get("ADMIN_HASH", "")
if admin:
    updates["ADMIN_PASSWORD_HASH"] = admin
lines = text.splitlines()
out = []
seen = set()
for line in lines:
    m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
    if m and m.group(1) in updates:
        k = m.group(1)
        out.append(f"{{k}}={{updates[k]}}")
        seen.add(k)
    else:
        out.append(line)
for k, v in updates.items():
    if k not in seen:
        out.append(f"{{k}}={{v}}")
p.write_text("\\n".join(out) + "\\n", encoding="utf-8")
PYENV
chown threatscope:threatscope {APP_DIR}/.env
chmod 600 {APP_DIR}/.env

echo "=== [6/10] Python venv + requirements ==="
if [ ! -d {APP_DIR}/venv ]; then
  sudo -u threatscope python3 -m venv {APP_DIR}/venv
fi
sudo -u threatscope {APP_DIR}/venv/bin/pip install -q -U pip wheel
sudo -u threatscope {APP_DIR}/venv/bin/pip install -q -r {APP_DIR}/requirements.txt

echo "=== [7/10] Feed ingest ==="
systemctl stop threatscope 2>/dev/null || true
sudo -u threatscope {APP_DIR}/venv/bin/python {APP_DIR}/ingest_feeds.py

echo "=== [8/10] systemd + nginx ==="
install -m 644 {APP_DIR}/deploy/systemd/threatscope.service /etc/systemd/system/threatscope.service
install -m 644 {APP_DIR}/deploy/nginx/threatscope-ip.conf /etc/nginx/sites-available/threatscope
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
curl -sf http://127.0.0.1:8000/health || (journalctl -u threatscope -n 40 --no-pager; exit 1)
echo "HEALTH_OK"
"""


def connect() -> paramiko.SSHClient:
    host = DEFAULT_HOST
    user = DEFAULT_USER
    password = os.environ.get("DEPLOY_SSH_PASSWORD", "").strip()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {"hostname": host, "username": user, "timeout": 60}
    if password:
        kwargs["password"] = password
        kwargs["look_for_keys"] = False
        kwargs["allow_agent"] = False
    else:
        kwargs["allow_agent"] = True
        kwargs["look_for_keys"] = True
    client.connect(**kwargs)
    return client


def run_remote(script: str) -> int:
    client = connect()
    try:
        stdin, stdout, stderr = client.exec_command(
            "bash -s", get_pty=True, timeout=3600
        )
        stdin.write(script)
        stdin.channel.shutdown_write()
        out_chunks: list[str] = []
        err_chunks: list[str] = []
        while True:
            if stdout.channel.recv_ready():
                chunk = stdout.channel.recv(4096).decode("utf-8", errors="replace")
                sys.stdout.write(chunk)
                out_chunks.append(chunk)
            if stderr.channel.recv_stderr_ready():
                chunk = stderr.channel.recv_stderr(4096).decode(
                    "utf-8", errors="replace"
                )
                sys.stderr.write(chunk)
                err_chunks.append(chunk)
            if stdout.channel.exit_status_ready():
                if not stdout.channel.recv_ready() and not stderr.channel.recv_stderr_ready():
                    break
        code = stdout.channel.recv_exit_status()
        return code
    finally:
        client.close()


def main() -> int:
    admin_hash = os.environ.get("ADMIN_PASSWORD_HASH", "").strip()
    if not admin_hash:
        admin_hash = read_admin_hash_from_local_env()
    allowed = os.environ.get(
        "ALLOWED_HOSTS", f"{DEFAULT_HOST},localhost,127.0.0.1"
    )
    script = build_remote_script(admin_hash, allowed)
    print(f"Deploying to {DEFAULT_USER}@{DEFAULT_HOST} ...", flush=True)
    return run_remote(script)


if __name__ == "__main__":
    raise SystemExit(main())
