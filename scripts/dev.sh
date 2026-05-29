#!/usr/bin/env bash
# Start ThreatScope for local development.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d venv ]]; then
  python3 -m venv venv
  ./venv/bin/pip install -r requirements.txt
fi

if [[ ! -f data/threatscope.db ]]; then
  ./venv/bin/python seed_db.py
fi

export ENV="${ENV:-development}"

if ! curl -sf -m 2 http://127.0.0.1:11434/ >/dev/null 2>&1; then
  echo "Note: Ollama is not running — AI summaries will be unavailable."
  echo "      Terminal 1: ./scripts/start-ollama.sh  (uses .local/bin/, no sudo)"
  echo ""
fi

if [[ "${LAB_SCAN_ENABLED:-0}" != "1" ]]; then
  echo "Note: Lab nmap/ping is off (LAB_SCAN_ENABLED not set)."
  echo "      To enable: LAB_SCAN_ENABLED=1 in .env, restart this app, and in another terminal:"
  echo "        LAB_SCAN_ENABLED=1 ./venv/bin/python scripts/scan_worker.py"
  echo "      Run lab scan appears on IP/domain results after lookup."
  echo ""
fi

exec ./venv/bin/uvicorn main:app --host 127.0.0.1 --port "${PORT:-8000}" --reload
