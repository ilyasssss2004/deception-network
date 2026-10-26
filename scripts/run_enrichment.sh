#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

umask 077
mkdir -p "$ROOT/logs/automation"
chmod 700 "$ROOT/logs/automation"

LOGFILE="$ROOT/logs/automation/enrichment-$(date -u +%Y-%m).log"
exec >>"$LOGFILE" 2>&1

exec 9>/tmp/deception-network-jobs.lock
flock 9

on_error() {
    rc=$?
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] ENRICHMENT FAILED, exit=$rc"
    exit "$rc"
}
trap on_error ERR

echo
echo "Enrichment started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
python3 -u scripts/enrich_threat_intel.py --max-items 10
echo "Enrichment completed: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
