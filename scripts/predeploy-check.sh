#!/usr/bin/env bash
# Pre-deploy validation for ThreatScope production / public profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found (copy .env.production.example or .env.example)" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a
source .env
set +a

errors=0
warn=0

fail() { echo "ERROR: $*" >&2; errors=$((errors + 1)); }
warn_msg() { echo "WARN: $*" >&2; warn=$((warn + 1)); }

if [[ "${ENV:-development}" != "production" ]]; then
  warn_msg "ENV is not production"
fi

if [[ -z "${SECRET_KEY:-}" ]]; then
  fail "SECRET_KEY is empty (required in production)"
fi

if [[ -z "${ALLOWED_HOSTS:-}" ]]; then
  fail "ALLOWED_HOSTS is empty (required in production)"
fi

if [[ "${THREATSCOPE_PUBLIC:-0}" == "1" && "${THREATSCOPE_ADMIN:-0}" == "1" ]]; then
  fail "THREATSCOPE_PUBLIC=1 with THREATSCOPE_ADMIN=1 — use admin session login instead"
fi

if [[ "${THREATSCOPE_PUBLIC:-0}" == "1" ]]; then
  if [[ -z "${ADMIN_PASSWORD:-}" && -z "${ADMIN_PASSWORD_HASH:-}" ]]; then
    warn_msg "THREATSCOPE_PUBLIC=1 but no ADMIN_PASSWORD or ADMIN_PASSWORD_HASH (admin login disabled)"
  fi
fi

ollama_url="${OLLAMA_URL:-http://127.0.0.1:11434/api/generate}"
if [[ "$ollama_url" != *"127.0.0.1"* && "$ollama_url" != *"localhost"* ]]; then
  warn_msg "OLLAMA_URL should stay on localhost: $ollama_url"
fi

if [[ ! -f data/threatscope.db ]]; then
  warn_msg "data/threatscope.db missing — run: python ingest_feeds.py"
fi

if [[ "$errors" -gt 0 ]]; then
  echo "Pre-deploy check failed with $errors error(s), $warn warning(s)." >&2
  exit 1
fi

echo "Pre-deploy check passed ($warn warning(s))."
exit 0
