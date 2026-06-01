#!/usr/bin/env bash
# Lab-only: ingest SHA256 hashes from private sample git repos (see ingest_samples.py).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d venv ]]; then
  echo "venv not found — run: python -m venv venv && ./venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

if [[ ! -f data/sample_repos.yaml ]]; then
  echo "Missing data/sample_repos.yaml — copy from data/sample_repos.yaml.example" >&2
  exit 1
fi

exec ./venv/bin/python ingest_samples.py "$@"
