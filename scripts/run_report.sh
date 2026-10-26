#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

umask 077
mkdir -p "$ROOT/logs/automation" "$ROOT/reports/private"
chmod 700 "$ROOT/logs/automation" "$ROOT/reports/private"

LOGFILE="$ROOT/logs/automation/report-$(date -u +%Y-%m).log"
exec >>"$LOGFILE" 2>&1

exec 9>/tmp/deception-network-jobs.lock
flock 9

on_error() {
    rc=$?
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] REPORT FAILED, exit=$rc"
    exit "$rc"
}
trap on_error ERR

echo
echo "Report job started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
python3 -u scripts/generate_report.py "$@"
echo "Report job completed: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
