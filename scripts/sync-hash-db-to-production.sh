#!/usr/bin/env bash
# Sync lab SQLite (hash indicators) to production VPS — run from the lab machine.
#
# Safe procedure:
#   1. On VPS: sudo systemctl stop threatscope
#   2. Rsync DB to VPS (this script)
#   3. On VPS: sudo chown threatscope:threatscope /opt/threatscope/data/threatscope.db
#   4. On VPS: sudo systemctl start threatscope
#
# Usage:
#   VPS_HOST=167.233.16.244 VPS_USER=root ./scripts/sync-hash-db-to-production.sh
#   DRY_RUN=1 ./scripts/sync-hash-db-to-production.sh   # rsync --dry-run
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL_DB="${LOCAL_DB:-$ROOT/data/threatscope.db}"
VPS_HOST="${VPS_HOST:-167.233.16.244}"
VPS_USER="${VPS_USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/opt/threatscope/data}"
REMOTE_DB="${REMOTE_DIR}/threatscope.db"

if [[ ! -f "$LOCAL_DB" ]]; then
  echo "Local database not found: $LOCAL_DB" >&2
  exit 1
fi

RSYNC_OPTS=(-avz --progress)
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  RSYNC_OPTS+=(--dry-run)
fi

echo "=== Sync hash DB to ${VPS_USER}@${VPS_HOST} ==="
echo "Local:  $LOCAL_DB"
echo "Remote: ${VPS_USER}@${VPS_HOST}:${REMOTE_DB}"
echo ""
echo "Stop threatscope on the VPS before copying:"
echo "  ssh ${VPS_USER}@${VPS_HOST} 'systemctl stop threatscope'"
echo ""

read -r -p "Continue with rsync? [y/N] " ans
if [[ "${ans,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

rsync "${RSYNC_OPTS[@]}" "$LOCAL_DB" "${VPS_USER}@${VPS_HOST}:${REMOTE_DB}.new"
ssh "${VPS_USER}@${VPS_HOST}" "mv ${REMOTE_DB}.new ${REMOTE_DB} && chown threatscope:threatscope ${REMOTE_DB} && chmod 640 ${REMOTE_DB}"

echo ""
echo "Done. Restart on VPS:"
echo "  ssh ${VPS_USER}@${VPS_HOST} 'systemctl start threatscope'"
