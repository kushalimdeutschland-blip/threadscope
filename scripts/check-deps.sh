#!/usr/bin/env bash
# ThreatScope dependency check for homelab setup.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ok() { printf "  \033[32mOK\033[0m   %s\n" "$1"; }
warn() { printf "  \033[33mWARN\033[0m %s\n" "$1"; }
miss() { printf "  \033[31mMISS\033[0m %s\n" "$1"; }

echo "ThreatScope dependency check"
echo "============================"

# Python venv
if [[ -x "$ROOT/venv/bin/python3" ]] || [[ -d "$ROOT/venv/lib" ]]; then
  ok "Python venv present"
else
  miss "Python venv — run: python -m venv venv && pip install -r requirements.txt"
fi

PY="${PY:-python3.14}"
if ! command -v "$PY" &>/dev/null; then
  PY=python3
fi
export PYTHONPATH="$ROOT:$ROOT/venv/lib/python3.14/site-packages${PYTHONPATH:+:$PYTHONPATH}"

# Python packages
for pkg in fastapi pefile yara aiosqlite httpx dotenv; do
  if "$PY" -c "import $pkg" 2>/dev/null; then
    ok "Python package: $pkg"
  else
    miss "Python package: $pkg — pip install -r requirements.txt"
  fi
done

# YARA scan smoke
if "$PY" -c "
from services.yara_scan import scan_bytes, invalidate_rules_cache
invalidate_rules_cache()
r = scan_bytes(b'test')
assert r.status in ('ok','skipped','unavailable')
" 2>/dev/null; then
  ok "YARA scanner (yara-python + rules)"
else
  warn "YARA scanner failed — check data/yara_rules or run: python ingest_yara_rules.py"
fi

# Database
if [[ -f "$ROOT/data/threatscope.db" ]]; then
  ok "SQLite DB (data/threatscope.db)"
else
  warn "No DB yet — run: python ingest_feeds.py"
fi

# Androguard (optional APK depth)
if "$PY" -c "import androguard" 2>/dev/null; then
  ok "androguard (APK manifest parsing)"
else
  warn "androguard not installed — pip install androguard for full APK static analysis"
fi

# YARA rules on disk
if [[ -d "$ROOT/data/yara_rules" ]] && compgen -G "$ROOT/data/yara_rules/*.yar" >/dev/null 2>&1; then
  n=$(find "$ROOT/data/yara_rules" -name '*.yar' -o -name '*.yara' 2>/dev/null | wc -l)
  ok "YARA rules on disk ($n files)"
else
  warn "No data/yara_rules — run: python ingest_yara_rules.py (bootstrap rules work offline)"
fi

# System tools (optional)
echo ""
echo "Optional (homelab full stack):"
if command -v yara &>/dev/null; then
  ok "yara CLI ($(yara --version 2>/dev/null | head -1))"
else
  warn "yara CLI not in PATH (yara-python may still work) — Arch: sudo pacman -S yara"
fi

if [[ -x "$ROOT/.local/bin/bin/ollama" ]]; then
  ok "Local Ollama binary (.local/bin/bin/ollama)"
else
  warn "No local Ollama — run: ./scripts/install-ollama-local.sh (or sudo pacman -S ollama)"
fi

if curl -sf -m 2 http://127.0.0.1:11434/ >/dev/null 2>&1; then
  ok "Ollama reachable on :11434"
  if curl -sf -m 2 http://127.0.0.1:11434/api/tags 2>/dev/null | grep -q 'qwen2.5:1.5b'; then
    ok "Model qwen2.5:1.5b present"
  else
    warn "Model qwen2.5:1.5b missing — ./scripts/start-ollama.sh in one terminal, then:"
    warn "  $ROOT/.local/bin/bin/ollama pull qwen2.5:1.5b"
  fi
else
  warn "Ollama not running — terminal 1: ./scripts/start-ollama.sh"
fi

if command -v docker &>/dev/null; then
  ok "docker ($(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ','))"
  if curl -sf -m 2 http://127.0.0.1:8001/ >/dev/null 2>&1; then
    ok "MobSF reachable on :8001"
  else
    warn "MobSF not up — docker compose --profile mobsf up"
  fi
else
  warn "docker not installed — needed for MobSF APK sandbox (mock works without it)"
fi

echo ""
echo "Run tests: PYTHONPATH=.:venv/lib/python3.14/site-packages python3.14 -m pytest tests/ -q"
