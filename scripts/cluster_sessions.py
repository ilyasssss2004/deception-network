#!/usr/bin/env python3
"""Cluster Cowrie sessions using command-family and TTP similarity."""

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "deception.sqlite3"

RULES = [
    ("file_transfer", r"\b(wget|curl|tftp|ftp|scp|sftp)\b"),
    ("credential_access", r"/etc/(passwd|shadow)|authorized_keys|/\.ssh/|\b(chpasswd|sudoers)\b"),
    ("persistence", r"\b(crontab|useradd|adduser)\b|systemctl\s+enable"),
    ("network_discovery", r"\b(nmap|ping|traceroute|tracepath|ifconfig|netstat|arp|route)\b|\bip\s+(addr|address|route|link)\b|\bss\s+-"),
    ("process_discovery", r"\b(ps|top|htop|pgrep|pidof|lsof)\b"),
    ("permission_change", r"\b(chmod|chown|chattr|setfacl)\b"),
    ("execution", r"\b(bash|sh|python3?|perl|php|ruby|nc|ncat|socat)\b|(?:^|[\s;&|])\./[\w./-]+"),
    ("file_read", r"\b(cat|head|tail|less|more|grep|sed|awk)\b"),
    ("file_discovery", r"\b(ls|find|locate|tree|dir)\b"),
    ("host_discovery", r"\b(whoami|id|uname|hostname|pwd|env|history|date|uptime|df|free|mount)\b"),
]

IGNORED_FAMILIES = {"other", "session_end"}


def classify_command(command):
    """Return one primary command family and all matched behavior families."""
    text = (command or "").strip().lower()
    if not text:
        return None, set()

    matches = {
        family for family, pattern in RULES
        if re.search(pattern, text)
    }

    if re.fullmatch(r"(exit|logout|quit)", text):
        matches.add("session_end")

    if not matches:
        matches.add("other")

    primary = next(
        (family for family, _ in RULES if family in matches),
        "session_end" if "session_end" in matches else "other",
    )
    return primary, matches


def similarity(left, right):
    """Compare command-family sequences and meaningful behavior sets."""
    a = [x for x in left["sequence"] if x not in IGNORED_FAMILIES]
    b = [x for x in right["sequence"] if x not in IGNORED_FAMILIES]

    if len(a) < 2 or len(b) < 2:
        return False

    sequence_score = SequenceMatcher(
        None, a, b, autojunk=False
    ).ratio()

    features_a = left["ttps"] - IGNORED_FAMILIES
    features_b = right["ttps"] - IGNORED_FAMILIES
    union = features_a | features_b
    intersection = features_a & features_b
    jaccard_score = len(intersection) / len(union) if union else 0

    # Conservative heuristic: either similar sequences or strong overlap
    # across at least two meaningful behavior families.
    return (
        sequence_score >= 0.72
        or (len(intersection) >= 2 and jaccard_score >= 0.60)
    )


def find_groups(sessions):
    """Build deterministic clusters using pairwise similarity."""
    parents = {sid: sid for sid in sessions}

    def root(sid):
        while parents[sid] != sid:
            parents[sid] = parents[parents[sid]]
            sid = parents[sid]
        return sid

    def union(a, b):
        ra, rb = root(a), root(b)
        if ra != rb:
            parents[max(ra, rb)] = min(ra, rb)

    eligible = [
        sid for sid, data in sessions.items()
        if sum(
            f not in IGNORED_FAMILIES
            for f in data["sequence"]
        ) >= 2
    ]

    for i, a in enumerate(eligible):
        for b in eligible[i + 1:]:
            if similarity(sessions[a], sessions[b]):
                union(a, b)

    groups = defaultdict(list)
    for sid in sessions:
        groups[root(sid)].append(sid)

    assignments = {}
    for members in groups.values():
        members = sorted(members)

        if len(members) >= 2:
            fingerprint = hashlib.sha256(
                "|".join(members).encode()
            ).hexdigest()[:8]
            cluster_id = f"CL-{fingerprint}"
        else:
            sid = members[0]
            meaningful = [
                f for f in sessions[sid]["sequence"]
                if f not in IGNORED_FAMILIES
            ]
            cluster_id = (
                "UNCLUSTERED" if len(meaningful) >= 2
                else "INSUFFICIENT_DATA"
            )

        for sid in members:
            assignments[sid] = cluster_id

    return assignments


def main():
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}")

    with sqlite3.connect(DB_PATH) as db:
        rows = db.execute("""
            SELECT timestamp, eventid, session, src_ip, protocol, input
            FROM events
            WHERE source = 'cowrie'
              AND session IS NOT NULL AND session != ''
            ORDER BY timestamp
        """).fetchall()

        sessions = {}

        for timestamp, eventid, sid, src_ip, protocol, command in rows:
            data = sessions.setdefault(sid, {
                "protocols": Counter(),
                "source_ips": Counter(),
                "timestamps": [],
                "events": 0,
                "login_successes": 0,
                "login_failures": 0,
                "sequence": [],
                "ttps": set(),
            })

            data["events"] += 1

            if protocol:
                data["protocols"][protocol] += 1
            if src_ip:
                data["source_ips"][src_ip] += 1
            if timestamp:
                data["timestamps"].append(timestamp)

            if eventid == "cowrie.login.success":
                data["login_successes"] += 1
            elif eventid == "cowrie.login.failed":
                data["login_failures"] += 1

            if eventid == "cowrie.command.input" and command:
                family, tags = classify_command(command)
                if family:
                    data["sequence"].append(family)
                    data["ttps"].update(tags)

        if not sessions:
            print("No Cowrie sessions with session IDs were found.")
            return

        assignments = find_groups(sessions)

        db.execute("""
            CREATE TABLE IF NOT EXISTS session_analysis (
                session_id TEXT PRIMARY KEY,
                protocol TEXT,
                source_ip TEXT,
                first_seen TEXT,
                last_seen TEXT,
                event_count INTEGER NOT NULL,
                command_count INTEGER NOT NULL,
                login_successes INTEGER NOT NULL,
                login_failures INTEGER NOT NULL,
                command_families_json TEXT NOT NULL,
                ttp_tags_json TEXT NOT NULL,
                cluster_id TEXT NOT NULL,
                analyzed_at TEXT NOT NULL
            )
        """)

        # This is a derived table; the original events table is untouched.
        db.execute("DELETE FROM session_analysis")
        analyzed_at = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )

        for sid, data in sessions.items():
            protocols = data["protocols"]
            protocol = protocols.most_common(1)[0][0] if protocols else None

            ips = data["source_ips"]
            # This value stays in SQLite and is not printed below.
            source_ip = ips.most_common(1)[0][0] if ips else None

            times = sorted(data["timestamps"])
            db.execute("""
                INSERT INTO session_analysis (
                    session_id, protocol, source_ip,
                    first_seen, last_seen, event_count,
                    command_count, login_successes, login_failures,
                    command_families_json, ttp_tags_json,
                    cluster_id, analyzed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sid,
                protocol,
                source_ip,
                times[0] if times else None,
                times[-1] if times else None,
                data["events"],
                len(data["sequence"]),
                data["login_successes"],
                data["login_failures"],
                json.dumps(data["sequence"]),
                json.dumps(sorted(data["ttps"])),
                assignments[sid],
                analyzed_at,
            ))

        db.commit()

    clusters = defaultdict(list)
    for sid, cid in assignments.items():
        clusters[cid].append(sid)

    print("=== COWRIE BEHAVIORAL CLUSTERING ===")
    print(f"Sessions analyzed: {len(sessions)}")
    print(f"Sessions with command events: "
          f"{sum(bool(d['sequence']) for d in sessions.values())}")
    print(f"Sessions with insufficient behavioral data: "
          f"{sum(cid == 'INSUFFICIENT_DATA' for cid in assignments.values())}")
    print(f"Clusters with multiple sessions: "
          f"{sum(len(m) >= 2 for c, m in clusters.items() if c.startswith('CL-'))}")

    print("\n=== SESSION SUMMARIES ===")
    for sid in sorted(sessions):
        data = sessions[sid]
        protocol = (
            data["protocols"].most_common(1)[0][0]
            if data["protocols"] else "unknown"
        )
        short_id = sid[-8:]
        tags = sorted(data["ttps"] - IGNORED_FAMILIES)
        print(
            f"session=...{short_id} | protocol={protocol} | "
            f"events={data['events']} | "
            f"commands={len(data['sequence'])} | "
            f"behaviors={','.join(tags) if tags else 'none'} | "
            f"cluster={assignments[sid]}"
        )

    print("\nDerived results saved to SQLite table: session_analysis")
    print("No raw commands or passwords were added to that table.")
    print("Clusters are heuristic similarities, not proof of a shared attacker.")


if __name__ == "__main__":
    main()
