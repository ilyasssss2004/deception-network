#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

umask 077
mkdir -p "$ROOT/logs/automation"
chmod 700 "$ROOT/logs/automation"

LOGFILE="$ROOT/logs/automation/pipeline-$(date -u +%Y-%m).log"
exec >>"$LOGFILE" 2>&1

exec 9>/tmp/deception-network-jobs.lock
flock 9

on_error() {
    rc=$?
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] FAILED, exit=$rc"
    exit "$rc"
}
trap on_error ERR

echo
echo "=================================================="
echo "Pipeline started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "=================================================="

run_step() {
    local description="$1"
    shift

    echo
    echo ">>> $description"
    "$@"
    echo "<<< Completed: $description"
}

run_step "Ingest new honeypot events" \
    python3 -u scripts/ingest_cowrie.py

run_step "Analyze session behavior" \
    python3 -u scripts/cluster_sessions.py

run_step "Detect new credential pairs" \
    python3 -u scripts/credential_alerts.py

run_step "Detect new file hashes" \
    python3 -u scripts/hash_alerts.py

echo
echo "Pipeline completed: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
