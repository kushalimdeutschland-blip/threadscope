#!/usr/bin/env bash
# One-time host checks for CAPE dynamic analysis (EXE) on Linux.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== ThreatScope CAPE setup =="

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker and retry."
  exit 1
fi

if [[ -r /dev/kvm ]]; then
  echo "OK: /dev/kvm is available"
else
  echo "WARN: /dev/kvm not found. Enable KVM in BIOS and load kvm module."
  echo "      EXE dynamic analysis will fall back to mock in SANDBOX_BACKEND=auto."
fi

if command -v kvm-ok >/dev/null 2>&1; then
  kvm-ok || true
fi

if groups "$USER" | grep -qE '\b(kvm|libvirt)\b'; then
  echo "OK: user is in kvm/libvirt group"
else
  echo "TIP: add your user to kvm for CAPE:"
  echo "  sudo usermod -aG kvm \"$USER\""
  echo "  (log out and back in)"
fi

mkdir -p data/sandbox/cape data/uploads
chmod 700 data/uploads 2>/dev/null || true

echo ""
echo "Next steps:"
echo "  1. Set in .env: SANDBOX_BACKEND=auto (or cape)"
echo "  2. Start CAPE: docker compose --profile cape up"
echo "  3. Start worker: python scripts/sandbox_worker.py"
echo ""
echo "CAPE needs a Windows VM image configured inside the container — see:"
echo "  https://github.com/CAPEsandbox/CAPEv2/blob/master/docs/installation/"
