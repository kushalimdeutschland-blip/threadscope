#!/usr/bin/env bash
# Install Ollama into threatscope/.local/ (no sudo). Used by scripts/start-ollama.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${OLLAMA_VERSION:-0.6.5}"
ARCH="${OLLAMA_ARCH:-amd64}"
DEST="$ROOT/.local/bin"
BIN="$DEST/bin/ollama"
TMP="${TMPDIR:-/tmp}/ollama-install-$$"

mkdir -p "$DEST" "$TMP"
cd "$TMP"
trap 'rm -rf "$TMP"' EXIT

URL="https://github.com/ollama/ollama/releases/download/v${VERSION}/ollama-linux-${ARCH}.tgz"
echo "Downloading Ollama v${VERSION} (${ARCH})..."
curl -fsSL -o ollama.tgz "$URL"
tar -xzf ollama.tgz
if [[ -f bin/ollama ]]; then
  install -m 755 bin/ollama "$BIN"
elif [[ -f ollama ]]; then
  install -m 755 ollama "$BIN"
else
  echo "Unexpected archive layout:" >&2
  find . -maxdepth 2 -type f >&2
  exit 1
fi

echo "Installed: $BIN"
"$BIN" --version 2>/dev/null || true
echo ""
echo "Next:"
echo "  ./scripts/start-ollama.sh          # terminal 1"
echo "  $BIN pull qwen2.5:1.5b             # once serve is running"
