#!/usr/bin/env bash
# Start Ollama bound to localhost only (safe for dev and VPS).
# Prefers project-local install: .local/bin/ (no sudo, no global PATH).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL_DIR="$ROOT/.local/bin"
OLLAMA_BIN="${OLLAMA_BIN:-$LOCAL_DIR/bin/ollama}"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"

if [[ -x "$OLLAMA_BIN" ]]; then
  echo "Using local Ollama: $OLLAMA_BIN"
  echo "Listening on $OLLAMA_HOST (Ctrl+C to stop)"
  echo "Model for ThreatScope: qwen2.5:1.5b — pull once in another terminal:"
  echo "  OLLAMA_HOST=$OLLAMA_HOST $OLLAMA_BIN pull qwen2.5:1.5b"
  cd "$LOCAL_DIR"
  exec ./bin/ollama serve
fi

if command -v ollama >/dev/null 2>&1; then
  echo "Using system ollama: $(command -v ollama)"
  exec ollama serve
fi

echo "Ollama not found under $LOCAL_DIR/bin/ollama" >&2
echo "Install locally (no sudo): ./scripts/install-ollama-local.sh" >&2
echo "Or system-wide: sudo pacman -S ollama" >&2
exit 1
