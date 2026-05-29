#!/usr/bin/env bash
# Intel collection ingest for ThreatScope (cron-friendly).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d venv ]]; then
  echo "venv not found — run: python -m venv venv && ./venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

exec ./venv/bin/python ingest_intel.py "$@"
