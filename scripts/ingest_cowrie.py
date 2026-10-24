#!/usr/bin/env python3
"""Normalize Cowrie and OpenCanary JSON events into one SQLite database."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]

COWRIE_LOG = (
    PROJECT_DIR / "data/cowrie-var/log/cowrie/cowrie.json"
)
OPENCANARY_LOG = (
    PROJECT_DIR / "data/opencanary-logs/opencanary.log"
)
DB_FILE = PROJECT_DIR / "data/deception.sqlite3"


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_hash TEXT PRIMARY KEY,
    timestamp TEXT,
    eventid TEXT NOT NULL,
    sensor TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    session TEXT,
    username TEXT,
    password TEXT,
    input TEXT,
    protocol TEXT,
    shasum TEXT,
    url TEXT,
    message TEXT,
    source TEXT NOT NULL DEFAULT 'cowrie',
    src_port INTEGER,
    dst_port INTEGER
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON events(timestamp);

CREATE INDEX IF NOT EXISTS idx_events_eventid
    ON events(eventid);

CREATE INDEX IF NOT EXISTS idx_events_src_ip
    ON events(src_ip);

CREATE INDEX IF NOT EXISTS idx_events_session
    ON events(session);

"""


INSERT_EVENT = """
INSERT OR IGNORE INTO events (
    event_hash, timestamp, eventid, sensor, src_ip, dst_ip,
    session, username, password, input, protocol, shasum,
    url, message, source, src_port, dst_port
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


OPEN_CANARY_TYPES = {
    2000: "opencanary.ftp.login_attempt",
    2001: "opencanary.ftp.auth_initiated",
    3000: "opencanary.http.get",
    5000: "opencanary.smb.audit",
    3001: "opencanary.http.post_login_attempt",
    3002: "opencanary.http.unimplemented_method",
    3003: "opencanary.http.redirect",
}


def normalize_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            # Cowrie timestamps and OpenCanary utc_time are UTC.
            parsed = parsed.replace(tzinfo=timezone.utc)

        return (
            parsed.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
    except ValueError:
        return value


def normalize_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None

    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def normalize_port(value: Any) -> int | None:
    try:
        port = int(value)
        return port if 0 <= port <= 65535 else None
    except (TypeError, ValueError):
        return None


def canonical_hash(value: dict[str, Any]) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def safe_cowrie_event(event: dict[str, Any]) -> dict[str, Any]:
    """Remove credential fields and sanitize authentication messages."""
    clean = dict(event)
    clean.pop("password", None)
    clean.pop("passwd", None)

    eventid = clean.get("eventid")
    if eventid in {"cowrie.login.failed", "cowrie.login.success"}:
        status = "succeeded" if eventid == "cowrie.login.success" else "failed"
        username = clean.get("username") or "(unknown)"
        clean["message"] = (
            f"Authentication {status} for username {username!r}; "
            "password redacted"
        )

    return clean


def migrate_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA)

    columns = {
        row[1] for row in connection.execute("PRAGMA table_info(events)")
    }

    # Safe migrations for an existing single-source database.
    if "source" not in columns:
        connection.execute(
            "ALTER TABLE events "
            "ADD COLUMN source TEXT NOT NULL DEFAULT 'cowrie'"
        )

    if "src_port" not in columns:
        connection.execute("ALTER TABLE events ADD COLUMN src_port INTEGER")

    if "dst_port" not in columns:
        connection.execute("ALTER TABLE events ADD COLUMN dst_port INTEGER")

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)"
    )


def iter_json(path: Path):
    """Yield JSON objects and count malformed or non-object records."""
    if not path.is_file():
        print(f"WARNING: log file not found: {path}", file=sys.stderr)
        return

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                yield None
                continue

            if not isinstance(event, dict):
                yield None
                continue

            yield event


def cowrie_row(event: dict[str, Any]) -> tuple:
    clean = safe_cowrie_event(event)

    return (
        canonical_hash(clean),
        normalize_timestamp(clean.get("timestamp")),
        str(clean.get("eventid") or "unknown"),
        clean.get("sensor"),
        normalize_ip(clean.get("src_ip")),
        normalize_ip(clean.get("dst_ip")),
        clean.get("session"),
        clean.get("username"),
        None,  # Never store plaintext passwords.
        clean.get("input"),
        clean.get("protocol"),
        clean.get("shasum") or clean.get("sha256"),
        clean.get("url"),
        clean.get("message"),
        "cowrie",
        normalize_port(clean.get("src_port")),
        normalize_port(clean.get("dst_port")),
    )


def opencanary_row(event: dict[str, Any]) -> tuple | None:
    try:
        logtype = int(event.get("logtype", 0))
    except (TypeError, ValueError):
        return None

    # Skip startup/info messages; ingest service/security events only.
    if logtype < 2000:
        return None

    logdata = event.get("logdata")
    if not isinstance(logdata, dict):
        logdata = {}

    is_smb = logtype == 5000
    path = logdata.get("PATH")
    host = logdata.get("HOSTNAME")
    username = logdata.get("USER") if is_smb else logdata.get("USERNAME")

    def safe_smb_field(name: str, limit: int = 200) -> str | None:
        value = logdata.get(name)
        if not isinstance(value, str):
            return None
        cleaned = " ".join(value.split())
        return cleaned[:limit] if cleaned else None

    smb_action = safe_smb_field("AUDITACTION") if is_smb else None
    smb_share = safe_smb_field("SHARENAME") if is_smb else None
    smb_filename = safe_smb_field("FILENAME") if is_smb else None
    smb_status = safe_smb_field("STATUS") if is_smb else None

    event_input = path if isinstance(path, str) else None
    if is_smb and event_input is None:
        event_input = smb_filename or smb_action

    eventid = OPEN_CANARY_TYPES.get(
        logtype, f"opencanary.logtype.{logtype}"
    )
    protocol = (
        "ftp" if logtype in (2000, 2001)
        else "smb" if is_smb
        else "http"
    )

    # Do not persist the nested raw payload: it may contain passwords.
    if logtype == 2000:
        message = "OpenCanary observed FTP login activity; credentials omitted"
    elif logtype == 2001:
        message = "OpenCanary observed FTP authentication; credentials omitted"
    elif logtype == 3001:
        message = "OpenCanary observed HTTP POST login activity; credentials omitted"
    elif logtype == 3000:
        message = "OpenCanary observed HTTP GET activity"
    elif logtype == 3002:
        message = "OpenCanary observed an unsupported HTTP method"
    elif logtype == 3003:
        message = "OpenCanary observed HTTP redirect activity"
    elif logtype == 5000:
        details = []
        for label, value in (
            ("action", smb_action),
            ("share", smb_share),
            ("status", smb_status),
            ("file", smb_filename),
        ):
            if value:
                details.append(f"{label}={value}")
        message = "OpenCanary observed SMB audit activity"
        if details:
            message += "; " + "; ".join(details)
    else:
        message = f"OpenCanary event type {logtype}; raw payload omitted"

    timestamp = normalize_timestamp(
        event.get("utc_time") or event.get("local_time")
    )
    src_ip = normalize_ip(event.get("src_host"))
    dst_ip = normalize_ip(event.get("dst_host"))
    src_port = normalize_port(event.get("src_port"))
    dst_port = normalize_port(event.get("dst_port"))

    # Include only sanitized, normalized fields in the identity hash.
    identity = {
        "source": "opencanary",
        "timestamp": timestamp,
        "eventid": eventid,
        "sensor": event.get("node_id"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "username": username,
        "input": event_input,
        "protocol": protocol,
    }

    url = None
    if isinstance(host, str) and isinstance(path, str):
        url = f"http://{host}{path}"[:2048]

    return (
        canonical_hash(identity),
        timestamp,
        eventid,
        event.get("node_id"),
        src_ip,
        dst_ip,
        None,  # OpenCanary has no Cowrie session ID.
        username if isinstance(username, str) else None,
        None,  # Never store plaintext passwords.
        event_input,
        protocol,
        None,
        url,
        message,
        "opencanary",
        src_port,
        dst_port,
    )


def display_summary(connection: sqlite3.Connection) -> None:
    total = connection.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0]

    print("\nDatabase summary")
    print("----------------")
    print("Total events:", total)

    print("\nEvents by source")
    for source, count in connection.execute(
        "SELECT source, COUNT(*) FROM events "
        "GROUP BY source ORDER BY source"
    ):
        print(f"  {source}: {count}")

    print("\nEvents by type")
    for eventid, count in connection.execute(
        "SELECT eventid, COUNT(*) FROM events "
        "GROUP BY eventid ORDER BY COUNT(*) DESC, eventid LIMIT 20"
    ):
        print(f"  {eventid}: {count}")

    print("\nSessions by source IP")
    for src_ip, count in connection.execute(
        "SELECT COALESCE(src_ip, '(unknown)'), "
        "COUNT(DISTINCT session) FROM events "
        "WHERE session IS NOT NULL "
        "GROUP BY src_ip ORDER BY COUNT(DISTINCT session) DESC"
    ):
        print(f"  {src_ip}: {count} session(s)")

    missing_passwords = connection.execute(
        "SELECT COUNT(*) FROM events WHERE password IS NOT NULL"
    ).fetchone()[0]
    print("\nRows with plaintext password field:", missing_passwords)


def main() -> int:
    if not COWRIE_LOG.is_file():
        print(f"ERROR: Cowrie log not found: {COWRIE_LOG}", file=sys.stderr)
        return 1

    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    previous_umask = os.umask(0o077)
    connection = None

    counters = {
        "cowrie_read": 0,
        "opencanary_read": 0,
        "inserted": 0,
        "duplicates": 0,
        "skipped": 0,
        "malformed": 0,
    }

    try:
        connection = sqlite3.connect(DB_FILE)
        os.chmod(DB_FILE, 0o600)
        migrate_schema(connection)

        for event in iter_json(COWRIE_LOG):
            counters["cowrie_read"] += 1

            if event is None:
                counters["malformed"] += 1
                continue

            row = cowrie_row(event)
            cursor = connection.execute(INSERT_EVENT, row)

            if cursor.rowcount:
                counters["inserted"] += 1
            else:
                counters["duplicates"] += 1

        for event in iter_json(OPENCANARY_LOG):
            counters["opencanary_read"] += 1

            if event is None:
                counters["malformed"] += 1
                continue

            row = opencanary_row(event)
            if row is None:
                counters["skipped"] += 1
                continue

            cursor = connection.execute(INSERT_EVENT, row)
            if cursor.rowcount:
                counters["inserted"] += 1
            else:
                counters["duplicates"] += 1

        connection.commit()
        os.chmod(DB_FILE, 0o600)

        print("Multi-source ingestion complete")
        print("-------------------------------")
        for key, value in counters.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

        display_summary(connection)
        return 0

    except (OSError, sqlite3.Error) as exc:
        if connection is not None:
            connection.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    finally:
        if connection is not None:
            connection.close()
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
