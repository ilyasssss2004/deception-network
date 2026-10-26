#!/usr/bin/env python3
"""Alert on previously unseen SHA-256 hashes from actual Cowrie file events."""

import argparse
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "deception.sqlite3"

FILE_EVENTS = (
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
)


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main():
    parser = argparse.ArgumentParser(
        description="Track new file hashes observed in Cowrie."
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="Register existing file hashes without producing alerts.",
    )
    args = parser.parse_args()

    if not DB_PATH.is_file():
        print("ERROR: SQLite database not found.")
        return 1

    with sqlite3.connect(DB_PATH) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS artifact_hash_alerts (
                sha256 TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                event_types TEXT NOT NULL,
                source_ip TEXT,
                session_id TEXT,
                event_count INTEGER NOT NULL,
                registered_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS artifact_alert_state (
                name TEXT PRIMARY KEY,
                initialized_at TEXT NOT NULL
            )
        """)

        initialized = db.execute("""
            SELECT initialized_at
            FROM artifact_alert_state
            WHERE name = 'cowrie_file_hashes'
        """).fetchone()

        if args.baseline and initialized:
            print("ERROR: Hash baseline already exists; refusing to reset it.")
            return 1

        if not args.baseline and not initialized:
            print("No hash baseline exists yet.")
            print("Run: python3 scripts/hash_alerts.py --baseline")
            return 1

        rows = db.execute("""
            SELECT shasum, timestamp, eventid, src_ip, session
            FROM events
            WHERE eventid IN (?, ?)
              AND shasum IS NOT NULL
              AND shasum != ''
            ORDER BY timestamp
        """, FILE_EVENTS).fetchall()

        # Aggregate valid SHA-256 values from completed file-transfer events.
        artifacts = {}
        invalid = 0

        for sha, timestamp, eventid, src_ip, session in rows:
            sha = sha.strip().lower()

            if not re.fullmatch(r"[0-9a-f]{64}", sha):
                invalid += 1
                continue

            item = artifacts.setdefault(sha, {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "types": set(),
                "source_ip": src_ip,
                "session": session,
                "count": 0,
            })

            if timestamp and (
                not item["first_seen"] or timestamp < item["first_seen"]
            ):
                item["first_seen"] = timestamp

            if timestamp and (
                not item["last_seen"] or timestamp > item["last_seen"]
            ):
                item["last_seen"] = timestamp

            item["types"].add(eventid)
            item["count"] += 1

            if not item["source_ip"] and src_ip:
                item["source_ip"] = src_ip
            if not item["session"] and session:
                item["session"] = session

        new_count = 0

        if args.baseline:
            for sha, item in artifacts.items():
                db.execute("""
                    INSERT INTO artifact_hash_alerts (
                        sha256, first_seen, last_seen, event_types,
                        source_ip, session_id, event_count, registered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sha,
                    item["first_seen"],
                    item["last_seen"],
                    ",".join(sorted(item["types"])),
                    item["source_ip"],
                    item["session"],
                    item["count"],
                    now_utc(),
                ))
                new_count += 1

            db.execute("""
                INSERT INTO artifact_alert_state (name, initialized_at)
                VALUES ('cowrie_file_hashes', ?)
            """, (now_utc(),))
            db.commit()

            print("Mode: BASELINE")
            print(f"Existing file hashes registered: {new_count}")
            print("Historical hashes did not generate alerts.")

        else:
            for sha, item in artifacts.items():
                existing = db.execute("""
                    SELECT 1 FROM artifact_hash_alerts WHERE sha256 = ?
                """, (sha,)).fetchone()

                if existing:
                    db.execute("""
                        UPDATE artifact_hash_alerts
                        SET last_seen = ?,
                            event_types = ?,
                            event_count = ?
                        WHERE sha256 = ?
                    """, (
                        item["last_seen"],
                        ",".join(sorted(item["types"])),
                        item["count"],
                        sha,
                    ))
                    continue

                db.execute("""
                    INSERT INTO artifact_hash_alerts (
                        sha256, first_seen, last_seen, event_types,
                        source_ip, session_id, event_count, registered_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sha,
                    item["first_seen"],
                    item["last_seen"],
                    ",".join(sorted(item["types"])),
                    item["source_ip"],
                    item["session"],
                    item["count"],
                    now_utc(),
                ))

                new_count += 1
                print(
                    "ALERT: New captured file hash | "
                    f"SHA-256={sha} | "
                    f"event_types={','.join(sorted(item['types']))} | "
                    f"source_ip={item['source_ip'] or 'unknown'}"
                )

            db.commit()
            print("Mode: NEW FILE-HASH ALERTS")
            print(f"New unique file hashes: {new_count}")

        print(f"Completed file-transfer events with hashes: {len(rows) - invalid}")
        print(f"Unique valid SHA-256 values: {len(artifacts)}")
        print(f"Invalid or non-SHA-256 values skipped: {invalid}")

        if not artifacts:
            print("No completed file artifacts are currently recorded.")
            print("No malware was fabricated or assumed.")

        print("Results stored in artifact_hash_alerts.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
