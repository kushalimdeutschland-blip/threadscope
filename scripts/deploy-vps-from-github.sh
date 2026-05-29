#!/usr/bin/env bash
# Deploy ThreatScope on a VPS via git clone/pull. No secrets in this file.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export VPS_HOST="${VPS_HOST:-167.233.16.244}"
export VPS_USER="${VPS_USER:-root}"
export THREATSCOPE_REPO_URL="${THREATSCOPE_REPO_URL:-https://github.com/kushalimdeutschland-blip/threadscope.git}"
export THREATSCOPE_BRANCH="${THREATSCOPE_BRANCH:-main}"
export LOCAL_ENV="${LOCAL_ENV:-$ROOT/.env}"
export ALLOWED_HOSTS="${ALLOWED_HOSTS:-$VPS_HOST,localhost,127.0.0.1}"

if [[ -z "${DEPLOY_SSH_PASSWORD:-}" ]]; then
  echo "DEPLOY_SSH_PASSWORD not set; trying SSH key auth." >&2
fi

SITE_PACKAGES="$ROOT/venv/lib/python3.14/site-packages"
if [[ -d "$SITE_PACKAGES" ]]; then
  export PYTHONPATH="${SITE_PACKAGES}${PYTHONPATH:+:$PYTHONPATH}"
fi
PY="$(command -v python3)"
if ! "$PY" -c "import paramiko" 2>/dev/null; then
  echo "Install paramiko: $ROOT/venv/bin/pip install paramiko" >&2
  exit 1
fi
exec "$PY" "$ROOT/scripts/deploy_vps_github.py"
