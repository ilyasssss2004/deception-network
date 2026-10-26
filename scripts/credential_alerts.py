#!/usr/bin/env python3
"""Detect newly observed credential pairs without storing plaintext passwords."""

import hashlib
import hmac
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "deception.sqlite3"
ENV_PATH = ROOT / ".env"

COWRIE_LOG = ROOT / "data/cowrie-var/log/cowrie/cowrie.json"
OPENCANARY_LOG = ROOT / "data/opencanary-logs/opencanary.log"

COWRIE_AUTH_EVENTS = {
    "cowrie.login.failed": "failed",
    "cowrie.login.success": "success",
}

OPEN_CANARY_AUTH_TYPES = {
    2000: ("ftp", "ftp.login_attempt"),
    2001: ("ftp", "ftp.auth_initiated"),
    3001: ("http", "http.post_login_attempt"),
}


def load_key():
    value = os.environ.get("CREDENTIAL_HMAC_KEY", "").strip()

    if not value and ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            name, sep, candidate = line.partition("=")
            if sep and name.strip() == "CREDENTIAL_HMAC_KEY":
                value = candidate.strip().strip('"').strip("'")
                break

    try:
        key = bytes.fromhex(value)
    except ValueError:
        key = b""

    if len(key) != 32:
        raise RuntimeError(
            "CREDENTIAL_HMAC_KEY is missing or invalid in .env"
        )

    return key


def timestamp_of(event, source):
    value = (
        event.get("timestamp") if source == "cowrie"
        else event.get("utc_time") or event.get("local_time")
    )

    if isinstance(value, str) and value:
        return value

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def string_value(mapping, names):
    """Find a string field without logging its value."""
    for name in names:
        value = mapping.get(name)
        if isinstance(value, str):
            return value
    return None


def extract_pair(event, source):
    """Return non-persisted credential fields for a supported auth event."""
    if source == "cowrie":
        event_type = event.get("eventid")
        if event_type not in COWRIE_AUTH_EVENTS:
            return None

        username = event.get("username")
        password = event.get("password")
        if password is None:
            password = event.get("passwd")

        protocol = event.get("protocol") or "unknown"
        event_type = str(event_type)

    else:
        try:
            logtype = int(event.get("logtype", 0))
        except (TypeError, ValueError):
            return None

        if logtype not in OPEN_CANARY_AUTH_TYPES:
            return None

        protocol, short_name = OPEN_CANARY_AUTH_TYPES[logtype]
        event_type = f"opencanary.{short_name}"

        logdata = event.get("logdata")
        if not isinstance(logdata, dict):
            logdata = {}

        username = string_value(
            logdata,
            ("USERNAME", "USER", "username", "user"),
        )
        password = string_value(
            logdata,
            ("PASSWORD", "PASS", "password", "pass"),
        )

        # Some formats may use top-level fields.
        if username is None:
            username = string_value(
                event, ("USERNAME", "USER", "username", "user")
            )
        if password is None:
            password = string_value(
                event, ("PASSWORD", "PASS", "password", "pass")
            )

    # Only process events that actually include a password field.
    if not isinstance(password, str):
        return None

    if not isinstance(username, str) or not username:
        username = "(unknown)"

    return {
        "source": source,
        "protocol": str(protocol),
        "event_type": event_type,
        "username": username,
        "password": password,
        "timestamp": timestamp_of(event, source),
    }


def fingerprint(pair, key):
    # Serialize deterministically and use HMAC to prevent simple offline guessing
    # of likely passwords from the stored fingerprint alone.
    material = json.dumps(
        [pair["username"], pair["password"]],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return hmac.new(key, material, hashlib.sha256).hexdigest()


def read_candidates(path, source, key, counters):
    if not path.is_file():
        counters["missing_logs"] += 1
        print(f"WARNING: {source} log file not found.")
        return

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                counters["malformed"] += 1
                continue

            if not isinstance(event, dict):
                counters["malformed"] += 1
                continue

            pair = extract_pair(event, source)
            if pair is None:
                continue

            counters["candidate_events"] += 1
            pair["fingerprint"] = fingerprint(pair, key)
            yield pair


def create_table(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS credential_pairs (
            fingerprint TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            source TEXT NOT NULL,
            protocol TEXT NOT NULL,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS credential_alert_history (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            alerted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            observed_at TEXT NOT NULL,
            source TEXT NOT NULL,
            protocol TEXT NOT NULL,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new'
        )
    """)
    db.commit()


def main():
    parser = argparse.ArgumentParser(
        description="Track new credential pairs without storing passwords."
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Register existing pairs without generating alerts. "
             "Allowed only when the tracking table is empty.",
    )
    args = parser.parse_args()

    if not DB_PATH.exists():
        print("ERROR: Project database not found.")
        return 1

    try:
        key = load_key()
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 1

    counters = {
        "candidate_events": 0,
        "malformed": 0,
        "missing_logs": 0,
    }

    new_count = 0
    with sqlite3.connect(DB_PATH) as db:
        create_table(db)
        existing = db.execute(
            "SELECT COUNT(*) FROM credential_pairs"
        ).fetchone()[0]

        if args.baseline and existing:
            print("ERROR: Baseline already exists; refusing to reset it.")
            print("No credential records were changed.")
            return 1

        if not args.baseline and existing == 0:
            print("No baseline exists yet.")
            print("Run: python3 scripts/credential_alerts.py --baseline")
            return 1

        mode = "BASELINE" if args.baseline else "NEW-CREDENTIAL ALERTS"
        print(f"Mode: {mode}")

        sources = (
            (COWRIE_LOG, "cowrie"),
            (OPENCANARY_LOG, "opencanary"),
        )

        for path, source in sources:
            for pair in read_candidates(path, source, key, counters):
                fingerprint_value = pair["fingerprint"]

                cursor = db.execute("""
                    INSERT OR IGNORE INTO credential_pairs (
                        fingerprint, first_seen, source,
                        protocol, username, event_type
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    fingerprint_value,
                    pair["timestamp"],
                    pair["source"],
                    pair["protocol"],
                    pair["username"],
                    pair["event_type"],
                ))

                if not cursor.rowcount:
                    continue

                new_count += 1
                if not args.baseline:
                    # Persist alert metadata, never the plaintext password.
                    db.execute("""
                        INSERT OR IGNORE INTO credential_alert_history (
                            fingerprint, observed_at, source, protocol,
                            username, event_type
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        fingerprint_value,
                        pair["timestamp"],
                        pair["source"],
                        pair["protocol"],
                        pair["username"],
                        pair["event_type"],
                    ))

                    # Deliberately omit passwords and full fingerprints.
                    print(
                        "ALERT: New credential pair observed | "
                        f"source={pair['source']} | "
                        f"protocol={pair['protocol']} | "
                        f"username={pair['username']!r} | "
                        f"fingerprint={fingerprint_value[:10]}"
                    )

        db.commit()

    print("\nSummary")
    print("-------")
    print("Credential-bearing events examined:", counters["candidate_events"])
    print("Unique pairs newly registered:", new_count)
    print("Malformed log records skipped:", counters["malformed"])
    print("Missing log files:", counters["missing_logs"])
    print("Plaintext passwords stored: 0")

    if args.baseline:
        print("Historical pairs were registered without alerts.")
    elif new_count == 0:
        print("No previously unseen credential pairs were found.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
