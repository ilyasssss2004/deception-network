#!/usr/bin/env python3
"""Generate a private weekly security report from observed lab data."""

import argparse
import ipaddress
import json
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jinja2 import Environment
from markupsafe import Markup, escape

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "deception.sqlite3"
OUT_DIR = ROOT / "reports" / "private"

FILE_EVENTS = {
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
}
LOGIN_EVENTS = {
    "cowrie.login.success",
    "cowrie.login.failed",
    "opencanary.ftp.login_attempt",
    "opencanary.ftp.auth_initiated",
    "opencanary.http.post_login_attempt",
}

TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ report_title }}</title>
<style>
@page { size: A4; margin: 16mm 13mm; }
* { box-sizing: border-box; }
body { font: 11px/1.5 Arial, sans-serif; color: #243247; margin: 0; }
header { background: #10243a; color: #fff; padding: 25px; border-radius: 8px; }
header h1 { font-size: 24px; margin: 0 0 8px; }
header p { color: #d9e5f1; margin: 3px 0; }
h2 { color: #102d4b; font-size: 16px; margin: 24px 0 8px;
     border-bottom: 2px solid #dbe5ee; padding-bottom: 5px; }
h3 { color: #244969; font-size: 12px; margin: 13px 0 5px; }
.metrics { display: grid; grid-template-columns: repeat(4, 1fr);
           gap: 8px; margin: 16px 0; }
.metric { border: 1px solid #d9e2ec; padding: 11px; border-radius: 6px; }
.metric strong { display: block; color: #102d4b; font-size: 21px; }
.metric span { color: #53657a; font-size: 10px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 14px; }
th { background: #eaf0f6; color: #19344f; text-align: left; }
th, td { padding: 6px 7px; border-bottom: 1px solid #dce4ec;
         overflow-wrap: anywhere; vertical-align: top; }
tr { break-inside: avoid; }
.note { background: #f2f5f8; border-left: 3px solid #557796;
        padding: 9px 12px; margin: 9px 0; }
.muted { color: #637186; }
.status { font-weight: bold; }
footer { margin-top: 25px; padding-top: 8px; border-top: 1px solid #dce4ec;
         color: #637186; font-size: 9px; }
@media print {
  header { border-radius: 0; print-color-adjust: exact; }
  .metrics { grid-template-columns: repeat(4, 1fr); }
  h2 { break-after: avoid; }
}
</style>
</head>
<body>
<header>
  <h1>Deception Network</h1>
  <p><strong>{{ report_title }}</strong></p>
  <p>Period: {{ period_start }} to {{ report_time }} (UTC)</p>
  <p>Generated: {{ generated_at }} (UTC)</p>
  <p>Scope: Cowrie, OpenCanary and SMB honeypot telemetry</p>
</header>

<div class="metrics">
  <div class="metric"><strong>{{ weekly_events }}</strong><span>Events in period</span></div>
  <div class="metric"><strong>{{ total_events }}</strong><span>Total stored events</span></div>
  <div class="metric"><strong>{{ unique_ips }}</strong><span>Unique source IPs</span></div>
  <div class="metric"><strong>{{ weekly_sessions }}</strong><span>Analyzed sessions in period</span></div>
</div>

<h2>1. Executive summary</h2>
<p>This report summarizes honeypot telemetry and associated security
analysis for the selected reporting period.</p>
<ul>
  <li>{{ source_count }} event source(s) recorded activity in the period.</li>
  <li>{{ public_ip_count }} globally routable source IP(s) were observed.</li>
  <li>{{ file_event_count }} completed Cowrie file-transfer event(s) were recorded.</li>
  <li>{{ ti_count }} threat-intelligence result(s) are available for eligible
indicators observed during the period.</li>
</ul>
{% if public_ip_count == 0 %}
<div class="note"><strong>Data limitation:</strong> No globally routable source IPs
were observed in this period. The recorded source IPs are private, local or
otherwise non-global, so public IP reputation lookups were not performed.</div>
{% endif %}
{% if file_event_count == 0 %}
<div class="note"><strong>Data limitation:</strong> No completed Cowrie file
uploads or downloads were recorded. This report therefore makes no malware
detection claim.</div>
{% endif %}

<h2>2. Activity by source and protocol</h2>
<h3>Event sources</h3>
{{ source_table }}
<h3>Protocols</h3>
{{ protocol_table }}
<h3>Most frequent event types</h3>
{{ event_type_table }}
<h3>Activity by honeypot and protocol</h3>
{{ honeypot_protocol_table }}
<p class="muted">Event types shown here are recorded telemetry, not a conclusion
that an attack succeeded.</p>
<h3>Representative HTTP, FTP and SMB activity</h3>
<p>Selected service interactions are shown below. Duplicate details are
collapsed, and full internal SMB filesystem paths are not exposed.</p>
<p><strong>Recorded OpenCanary service events:</strong>
{{ service_activity_count }}</p>
{{ service_activity_table }}

<h2>3. Source IP activity</h2>
{% if ip_rows %}
<table><thead><tr><th>Source IP</th><th>Classification</th><th>Events</th></tr></thead>
<tbody>
{% for item in ip_rows %}
<tr><td>{{ item.ip }}</td><td>{{ item.kind }}</td><td>{{ item.count }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}
<p class="muted">No source IP activity with a valid timestamp in the selected period.</p>
{% endif %}

<h2>4. Geographic context</h2>
{% if country_rows %}
<p>Country codes below are derived from available stored threat-intelligence
results for observed IPs. They represent provider-supplied context, not
independently verified physical locations.</p>
{{ country_table }}
{% else %}
<p>No country attribution is available for the selected period. The report
does not infer attacker countries from private IP addresses.</p>
{% endif %}

<h2>5. Authentication activity</h2>
<p>Passwords are never included in this report. Usernames below are drawn from
recorded login-related events; an event's presence does not by itself prove
that the credentials were valid.</p>
{% if username_rows %}
<table><thead><tr><th>Username</th><th>Recorded login-related events</th></tr></thead>
<tbody>
{% for item in username_rows %}
<tr><td>{{ item.username }}</td><td>{{ item.count }}</td></tr>
{% endfor %}
</tbody></table>
{% else %}
<p class="muted">No login usernames were available in the selected period.</p>
{% endif %}
<p>Distinct credential pairs tracked to date:
<strong>{{ credential_registry_count }}</strong>.</p>

<h2>6. Behavioral analysis</h2>
<p>Sessions are grouped using command-family and TTP similarity heuristics.
A cluster is not proof of a shared attacker or campaign.</p>
{% if cluster_rows %}
<table><thead><tr><th>Cluster</th><th>Sessions</th><th>Protocols</th>
<th>Commands categorized</th><th>Behavior families</th></tr></thead>
<tbody>
{% for item in cluster_rows %}
<tr><td>{{ item.cluster }}</td><td>{{ item.sessions }}</td>
<td>{{ item.protocols }}</td><td>{{ item.commands }}</td>
<td>{{ item.behaviors }}</td></tr>
{% endfor %}
</tbody></table>
<p class="muted">Latest clustering analysis timestamp: {{ cluster_analyzed_at }}</p>
{% else %}
<p class="muted">No analyzed sessions fell within the selected period, or the
session-analysis table has not been populated.</p>
{% endif %}

<h2>7. Representative command activity</h2>
<p>Command-related events with recorded input during the reporting period:
<strong>{{ command_event_count }}</strong>. The table shows up to 12 distinct
recent command examples rather than every routine command.</p>
<p class="muted">Common credential-like arguments and URL query strings are
redacted where recognized. This is a best-effort redaction, so review the private
report before sharing it.</p>
{% if command_activity_rows %}
{{ command_activity_table }}
{% else %}
<p class="muted">No command input with a recorded value was found in this period.</p>
{% endif %}

<h2>8. File artifacts and malware intelligence</h2>
<p>Completed Cowrie file-transfer events in this period:
<strong>{{ file_event_count }}</strong>.</p>
<p>Distinct SHA-256 hashes observed in those events:
<strong>{{ file_hash_count }}</strong>.</p>
<p>New file hashes registered by the tracker during this period:
<strong>{{ tracked_hash_count }}</strong>.</p>
{% if artifact_rows %}
{{ artifact_table }}
{% else %}
<p>No captured file artifacts were recorded during this reporting period.</p>
{% endif %}
<p class="muted">Provider findings reflect the latest available analysis for each
captured file hash. A detection count is not, by itself, a complete malware verdict.</p>

<h2>9. Threat intelligence</h2>
{% if ti_rows %}
{{ ti_table }}
{% else %}
<p>No provider findings are available for eligible indicators observed during
this reporting period.</p>
{% endif %}

<h2>10. Alerting status and limitations</h2>
<p>New credential alerts recorded during this period:
<strong>{{ credential_alert_count }}</strong>.</p>
{% if credential_alert_rows %}
{{ credential_alert_table }}
{% else %}
<p class="muted">No persistent credential alerts were recorded during this period.
The credential fingerprint registry currently contains
{{ credential_registry_count }} distinct pairs.</p>
{% endif %}
<ul>
  <li>Credential-pair tracking uses keyed fingerprints; plaintext passwords are not retained.</li>
  <li>File analysis is based on captured file-transfer artifacts and available provider findings.</li>
  <li>Source-IP reputation findings are shown only for eligible observed indicators.</li>
  <li>Credential-alert history begins when persistent alert tracking was introduced;
  earlier console alerts are not automatically backfilled.</li>
</ul>

<footer>
  Generated locally from the project's SQLite database. Treat this as an internal
  lab report. Review and sanitize it before publishing any version to GitHub.
</footer>
</body>
</html>
"""


def parse_time(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def table_html(rows, headers):
    """Build safe HTML tables, escaping all dynamic cell values."""
    if not rows:
        return Markup('<p class="muted">No records available.</p>')

    result = ["<table><thead><tr>"]
    result.extend(
        f"<th>{escape(str(header))}</th>" for header in headers
    )
    result.append("</tr></thead><tbody>")

    for row in rows:
        result.append("<tr>")
        result.extend(
            f"<td>{escape('' if value is None else str(value))}</td>"
            for value in row
        )
        result.append("</tr>")

    result.append("</tbody></table>")
    return Markup("".join(result))

def table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone() is not None



def honeypot_label(source, protocol):
    """Map stored sensor names to human-readable deployed honeypots."""
    source_name = (source or "unknown").strip().lower()
    protocol_name = (protocol or "unknown").strip().lower()

    if source_name == "cowrie":
        return "Cowrie"
    if source_name == "opencanary" and protocol_name == "smb":
        return "OpenCanary SMB audit (Samba share)"
    if source_name == "opencanary":
        return "OpenCanary"
    if source_name == "samba":
        return "Samba"
    return source_name.replace("_", " ").title()


def protocol_label(protocol):
    names = {
        "ssh": "SSH",
        "telnet": "Telnet",
        "http": "HTTP",
        "ftp": "FTP",
        "smb": "SMB",
    }
    raw = (protocol or "unknown").strip().lower()
    return names.get(raw, raw.upper())


def safe_command_preview(value):
    """Shorten and redact common credential-shaped command arguments."""
    command = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    command = re.sub(r"\s+", " ", command).strip()

    command = re.sub(
        r'(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\b'
        r'(\s*[:=]\s*|\s+)(?:"[^"]*"|\'[^\']*\'|[^\s;&|]+)',
        r'\1\2[REDACTED]',
        command,
    )
    command = re.sub(
        r'(?i)(--?(?:password|passwd|token|secret|api[-_]?key)(?:=|\s+))'
        r'("[^"]*"|\'[^\']*\'|\S+)',
        r'\1[REDACTED]',
        command,
    )
    command = re.sub(
        r'(?i)(\b(?:curl|wget)\b.*?\s-u\s+)(\S+:\S+)',
        r'\1[REDACTED]',
        command,
    )
    command = re.sub(
        r'(?i)(\bsshpass\b.*?\s-p\s+)\S+',
        r'\1[REDACTED]',
        command,
    )
    command = re.sub(
        r'(https?://)[^/\s:@]+:[^/\s@]+@',
        r'\1[REDACTED]@',
        command,
    )
    command = re.sub(
        r'(https?://[^\s?#]+)[?#][^\s]*',
        r'\1?[REDACTED]',
        command,
    )

    if len(command) > 180:
        command = command[:177] + "..."
    return command or "(empty command)"



def safe_service_detail(eventid, protocol, url, input_value, message):
    """Summarize OpenCanary activity without exposing secrets or host paths."""
    eventid = str(eventid or "")
    message = str(message or "").replace("\r", " ").replace("\n", " ")

    if eventid == "opencanary.smb.audit":
        def field(name):
            match = re.search(
                rf"(?:^|;\s*){name}=([^;]+)", message, flags=re.IGNORECASE
            )
            return match.group(1).strip() if match else None

        parts = ["SMB audit"]
        for name in ("action", "share", "status"):
            value = field(name)
            if value:
                parts.append(f"{name}={value[:90]}")

        file_value = field("file")
        if file_value:
            root = "/srv/deception-smb/decoyshare"
            if file_value == root:
                display_file = "(share root)"
            elif file_value.startswith(root + "/"):
                display_file = file_value[len(root) + 1:]
            elif file_value.startswith("/"):
                display_file = Path(file_value).name
            else:
                display_file = file_value

            parts.append(f"item={display_file[:100]}")

        return "; ".join(parts)

    if eventid == "opencanary.http.get":
        raw_url = str(url or "/")
        raw_url = re.sub(r"(?i)^https?://[^/]+", "", raw_url)
        raw_url = re.split(r"[?#]", raw_url, maxsplit=1)[0] or "/"
        detail = f"HTTP GET {raw_url[:120]}"

        if input_value:
            detail += f"; recorded input={safe_command_preview(input_value)[:90]}"
        return detail[:220]

    # FTP and other service messages use the existing command-style redactor.
    raw = message or str(input_value or eventid)
    return safe_command_preview(raw)[:220]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=7,
                        help="Reporting window in days (default: 7).")
    parser.add_argument(
        "--tag",
        help="Optional safe output tag, e.g. validation, to keep test reports separate.",
    )
    args = parser.parse_args()

    if args.tag and not re.fullmatch(r"[a-zA-Z0-9_-]{1,40}", args.tag):
        parser.error("--tag must contain only letters, digits, underscores or hyphens")

    period_name = "Weekly" if args.days == 7 else f"{args.days}-Day"
    report_title = f"{period_name} Security Activity Report"
    if args.tag:
        label = args.tag.replace("_", " ").replace("-", " ").title()
        report_title = f"{label} — {period_name} Security Activity Report"

    if args.days < 1 or args.days > 366:
        parser.error("--days must be between 1 and 366")
    if not DB_PATH.exists():
        print(f"ERROR: Database not found: {DB_PATH}")
        return 1

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=args.days)

    with sqlite3.connect(DB_PATH) as db:
        total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        all_events = db.execute("""
            SELECT timestamp, eventid, source, src_ip, protocol, username
            FROM events
        """).fetchall()

        weekly = []
        for row in all_events:
            event_time = parse_time(row[0])
            if event_time and cutoff <= event_time <= now:
                weekly.append(row)

        # Summarize observed activity by sensor/honeypot and protocol.
        hp_buckets = defaultdict(
            lambda: {"events": 0, "ips": set(), "types": Counter()}
        )
        for row in weekly:
            source_raw = row[2] or "unknown"
            protocol_raw = row[4] or "unknown"
            key = (
                honeypot_label(source_raw, protocol_raw),
                protocol_label(protocol_raw),
            )
            bucket = hp_buckets[key]
            bucket["events"] += 1
            if row[3]:
                bucket["ips"].add(row[3])
            bucket["types"][row[1] or "unknown"] += 1

        honeypot_protocol_rows = []
        for (sensor_name, proto), bucket in sorted(hp_buckets.items()):
            common_types = "; ".join(
                f"{event} ({count})"
                for event, count in bucket["types"].most_common(3)
            )
            honeypot_protocol_rows.append((
                sensor_name,
                proto,
                bucket["events"],
                len(bucket["ips"]),
                common_types or "none recorded",
            ))

        # Read only command-input/failure events; never execute their contents.
        command_records = db.execute("""
            SELECT timestamp, eventid, source, src_ip, protocol, session, input
            FROM events
            WHERE eventid IN (?, ?)
              AND input IS NOT NULL
              AND TRIM(input) != ''
        """, (
            "cowrie.command.input",
            "cowrie.command.failed",
        )).fetchall()

        period_commands = []
        for record in command_records:
            event_time = parse_time(record[0])
            if event_time and cutoff <= event_time <= now:
                period_commands.append((event_time, record))

        period_commands.sort(key=lambda item: item[0], reverse=True)
        command_event_count = len(period_commands)
        command_activity_rows = []
        seen_command_examples = set()

        event_labels = {
            "cowrie.command.input": "Command input",
            "cowrie.command.failed": "Failed command",
        }

        for event_time, record in period_commands:
            timestamp, eventid, source_raw, src_ip, proto_raw, session, raw_input = record
            preview = safe_command_preview(raw_input)
            proto = protocol_label(proto_raw)
            sensor_name = honeypot_label(source_raw, proto_raw)

            # Keep distinct examples, not repeated copies of the same command.
            dedupe_key = (sensor_name, proto, eventid, preview)
            if dedupe_key in seen_command_examples:
                continue
            seen_command_examples.add(dedupe_key)

            session_label = str(session) if session else "not recorded"
            if session_label != "not recorded":
                session_label = session_label[:12]

            command_activity_rows.append((
                event_time.strftime("%Y-%m-%d %H:%M:%S"),
                sensor_name,
                proto,
                src_ip or "not recorded",
                session_label,
                event_labels.get(eventid, eventid or "unknown"),
                preview,
            ))
            if len(command_activity_rows) >= 12:
                break

        service_activity_count = 0
        service_candidates = []
        seen_service_rows = set()

        service_events = db.execute("""
            SELECT timestamp, eventid, source, src_ip, src_port,
                   dst_port, protocol, url, input, message
            FROM events
            WHERE source = 'opencanary'
              AND eventid IN (
                  'opencanary.http.get',
                  'opencanary.ftp.login_attempt',
                  'opencanary.smb.audit'
              )
        """).fetchall()

        for row in service_events:
            (timestamp, eventid, source_raw, src_ip, src_port, dst_port,
             proto_raw, url, input_value, message) = row

            event_time = parse_time(timestamp)
            if not event_time or not (cutoff <= event_time <= now):
                continue

            service_activity_count += 1
            detail = safe_service_detail(
                eventid, proto_raw, url, input_value, message
            )
            sensor_name = honeypot_label(source_raw, proto_raw)
            source_endpoint = str(src_ip or "not recorded")
            if src_port:
                source_endpoint += f":{src_port}"

            key = (eventid, source_endpoint, dst_port, detail)
            if key in seen_service_rows:
                continue
            seen_service_rows.add(key)

            service_candidates.append((
                event_time,
                (
                    event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    sensor_name,
                    protocol_label(proto_raw),
                    source_endpoint,
                    dst_port if dst_port is not None else "not recorded",
                    eventid,
                    detail,
                ),
            ))

        service_candidates.sort(key=lambda item: item[0], reverse=True)
        service_activity_rows = [
            item[1] for item in service_candidates[:12]
        ]

        source_counts = Counter((r[2] or "unknown") for r in weekly)
        protocol_counts = Counter((r[4] or "unknown") for r in weekly)
        event_counts = Counter((r[1] or "unknown") for r in weekly)
        ip_counts = Counter(r[3] for r in weekly if r[3])
        weekly_ips = set(ip_counts)

        ip_rows = []
        public_ips = set()
        for ip, count in ip_counts.most_common(10):
            try:
                parsed = ipaddress.ip_address(ip)
                is_public = parsed.is_global
            except ValueError:
                is_public = False
            if is_public:
                public_ips.add(ip)
            ip_rows.append({
                "ip": ip,
                "count": count,
                "kind": "Globally routable" if is_public
                        else "Private/local/reserved",
            })

        auth_counts = Counter()
        for row in weekly:
            eventid, username = row[1], row[5]
            if eventid in LOGIN_EVENTS and username:
                auth_counts[username] += 1
        username_rows = [
            {"username": name, "count": count}
            for name, count in auth_counts.most_common(15)
        ]

        file_events = [
            r for r in weekly if r[1] in FILE_EVENTS
        ]
        file_hash_counts = Counter()
        for sha, timestamp in db.execute("""
            SELECT shasum, timestamp FROM events
            WHERE eventid IN (?, ?)
              AND shasum IS NOT NULL AND shasum != ''
        """, tuple(FILE_EVENTS)):
            event_time = parse_time(timestamp)
            normalized = str(sha).strip().lower()
            if (
                event_time
                and cutoff <= event_time <= now
                and re.fullmatch(r"[0-9a-f]{64}", normalized)
            ):
                file_hash_counts[normalized] += 1

        file_hashes = set(file_hash_counts)

        credential_registry_count = (
            db.execute("SELECT COUNT(*) FROM credential_pairs").fetchone()[0]
            if table_exists(db, "credential_pairs") else 0
        )
        credential_alert_candidates = []
        if table_exists(db, "credential_alert_history"):
            for row in db.execute("""
                SELECT alerted_at, observed_at, source, protocol, username,
                       event_type, substr(fingerprint, 1, 10), status
                FROM credential_alert_history
                ORDER BY alerted_at DESC
            """):
                alerted_at, observed_at, source, protocol, username, event_type, fp, status = row
                alert_time = parse_time(alerted_at)
                if not alert_time or not (cutoff <= alert_time <= now):
                    continue

                observed_time = parse_time(observed_at)
                credential_alert_candidates.append((
                    alert_time,
                    (
                        alert_time.strftime("%Y-%m-%d %H:%M:%S"),
                        observed_time.strftime("%Y-%m-%d %H:%M:%S")
                        if observed_time else (observed_at or "not recorded"),
                        source or "unknown",
                        protocol or "unknown",
                        username or "not recorded",
                        event_type or "unknown",
                        fp or "",
                        status or "new",
                    ),
                ))

        credential_alert_candidates.sort(
            key=lambda item: item[0], reverse=True
        )
        credential_alert_count = len(credential_alert_candidates)
        credential_alert_rows = [
            item[1] for item in credential_alert_candidates[:10]
        ]

        tracked_hash_count = 0
        if table_exists(db, "artifact_hash_alerts"):
            for (registered_at,) in db.execute(
                "SELECT registered_at FROM artifact_hash_alerts"
            ):
                registered = parse_time(registered_at)
                if registered and cutoff <= registered <= now:
                    tracked_hash_count += 1

        cluster_rows = []
        cluster_analyzed_at = "not available"
        weekly_sessions = 0
        if table_exists(db, "session_analysis"):
            sessions = []
            for row in db.execute("""
                SELECT session_id, protocol, first_seen, last_seen,
                       command_count, ttp_tags_json, cluster_id, analyzed_at
                FROM session_analysis
            """):
                session_id, protocol, first_seen, last_seen, commands, tags, cid, analyzed = row
                event_time = parse_time(last_seen) or parse_time(first_seen)
                if event_time and cutoff <= event_time <= now:
                    try:
                        tag_list = json.loads(tags or "[]")
                    except (TypeError, ValueError):
                        tag_list = []
                    sessions.append({
                        "protocol": protocol or "unknown",
                        "commands": commands or 0,
                        "tags": tag_list if isinstance(tag_list, list) else [],
                        "cluster": cid or "UNCLUSTERED",
                    })
                    if analyzed and (cluster_analyzed_at == "not available" or analyzed > cluster_analyzed_at):
                        cluster_analyzed_at = analyzed

            weekly_sessions = len(sessions)
            groups = defaultdict(list)
            for session in sessions:
                groups[session["cluster"]].append(session)

            for cid, members in sorted(groups.items(),
                                      key=lambda item: (-len(item[1]), item[0])):
                behaviors = Counter(
                    tag for member in members for tag in member["tags"]
                )
                cluster_rows.append({
                    "cluster": cid,
                    "sessions": len(members),
                    "protocols": ", ".join(sorted({
                        m["protocol"] for m in members
                    })),
                    "commands": sum(m["commands"] for m in members),
                    "behaviors": ", ".join(
                        name for name, _ in behaviors.most_common(8)
                    ) or "none recorded",
                })

        ti_rows = []
        ti_detail_rows = []
        country_for_ip = {}
        file_intel = {}

        if table_exists(db, "threat_intel_results"):
            for kind, indicator, provider, status, checked_at, summary_json in db.execute("""
                SELECT indicator_type, indicator, provider, status,
                       checked_at, summary_json
                FROM threat_intel_results
                ORDER BY indicator_type, indicator, provider
            """):
                if kind == "ip" and indicator not in public_ips:
                    continue
                if kind == "file_hash" and indicator not in file_hashes:
                    continue
                if kind not in {"ip", "file_hash"}:
                    continue

                try:
                    summary = json.loads(summary_json or "{}")
                except (TypeError, ValueError):
                    summary = {}

                if kind == "ip" and status == "ok":
                    country = summary.get("country_code") or summary.get("country")
                    if country and indicator not in country_for_ip:
                        country_for_ip[indicator] = country

                if kind == "file_hash" and provider == "VirusTotal":
                    file_intel[indicator] = (status, summary, checked_at)

                if status != "ok":
                    assessment = summary.get("message") or "No matching report"
                elif provider == "AbuseIPDB":
                    assessment = (
                        f"Abuse confidence: {summary.get('abuse_confidence_score', 'n/a')}; "
                        f"reports: {summary.get('total_reports', 'n/a')}; "
                        f"country: {summary.get('country_code') or 'n/a'}"
                    )
                elif provider == "GreyNoise":
                    assessment = (
                        f"Noise: {summary.get('noise', 'n/a')}; "
                        f"classification: {summary.get('classification') or 'n/a'}; "
                        f"RIOT: {summary.get('riot', 'n/a')}"
                    )
                elif provider == "VirusTotal":
                    stats = summary.get("analysis_stats") or {}
                    assessment = (
                        f"Malicious: {stats.get('malicious', 0)}; "
                        f"suspicious: {stats.get('suspicious', 0)}; "
                        f"harmless: {stats.get('harmless', 0)}; "
                        f"undetected: {stats.get('undetected', 0)}; "
                        f"reputation: {summary.get('reputation', 'n/a')}"
                    )
                else:
                    assessment = "Result available"

                shown_indicator = indicator
                if kind == "file_hash":
                    shown_indicator = indicator

                ti_detail_rows.append((
                    kind,
                    shown_indicator,
                    provider,
                    status,
                    assessment,
                    checked_at or "unknown",
                ))

        ti_rows = ti_detail_rows
        ti_count = len(ti_detail_rows)

        country_counts = Counter(country_for_ip.values())
        country_rows = [
            (country, count)
            for country, count in country_counts.most_common(10)
        ]

        ti_table = table_html(
            ti_detail_rows,
            ("Indicator type", "Observed indicator", "Provider",
             "Status", "Assessment", "Last checked (UTC)"),
        )

        artifact_table_rows = []
        for sha, occurrences in sorted(file_hash_counts.items()):
            record = file_intel.get(sha)
            if not record:
                assessment = "No VirusTotal file report stored"
                checked_at = "Not available"
            else:
                status, summary, checked_at = record
                stats = summary.get("analysis_stats") or {}
                if status != "ok":
                    assessment = "No existing VirusTotal file report"
                else:
                    assessment = (
                        f"Malicious: {stats.get('malicious', 0)}; "
                        f"suspicious: {stats.get('suspicious', 0)}; "
                        f"harmless: {stats.get('harmless', 0)}; "
                        f"undetected: {stats.get('undetected', 0)}"
                    )
                    name = summary.get("meaningful_name")
                    if name:
                        assessment += f"; name: {name}"

            artifact_table_rows.append((
                sha, occurrences, assessment, checked_at or "unknown"
            ))

        artifact_rows = artifact_table_rows
        artifact_table = table_html(
            artifact_table_rows,
            ("SHA-256", "Transfer events", "VirusTotal analysis", "Last checked (UTC)"),
        )

    source_table = table_html(
        [(s, n) for s, n in source_counts.most_common()],
        ("Source", "Events"),
    )
    protocol_table = table_html(
        [(s, n) for s, n in protocol_counts.most_common()],
        ("Protocol", "Events"),
    )
    event_type_table = table_html(
        [(s, n) for s, n in event_counts.most_common(12)],
        ("Event type", "Events"),
    )
    honeypot_protocol_table = table_html(
        honeypot_protocol_rows,
        ("Honeypot / sensor", "Protocol", "Events", "Unique source IPs",
         "Most frequent event types"),
    )
    service_activity_table = table_html(
        service_activity_rows,
        ("Time (UTC)", "Honeypot", "Protocol", "Source endpoint",
         "Destination port", "Event type", "Observed activity"),
    )
    command_activity_table = table_html(
        command_activity_rows,
        ("Time (UTC)", "Honeypot", "Protocol", "Source IP", "Session",
         "Activity", "Sanitized command preview"),
    )
    credential_alert_table = table_html(
        credential_alert_rows,
        ("Alert time (UTC)", "Observed time (UTC)", "Source", "Protocol",
         "Username", "Event type", "Fingerprint prefix", "Status"),
    )
    country_table = table_html(country_rows, ("Country code", "Unique IPs"))

    # Use Jinja autoescaping for all database-derived string values.
    env = Environment(autoescape=True)
    template = env.from_string(TEMPLATE)
    html = template.render(
        report_title=report_title,
        period_start=cutoff.strftime("%Y-%m-%d %H:%M"),
        report_time=now.strftime("%Y-%m-%d %H:%M"),
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
        weekly_events=len(weekly),
        total_events=total_events,
        unique_ips=len(weekly_ips),
        weekly_sessions=weekly_sessions,
        source_count=len(source_counts),
        public_ip_count=len(public_ips),
        file_event_count=len(file_events),
        file_hash_count=len(file_hashes),
        source_table=source_table,
        honeypot_protocol_table=honeypot_protocol_table,
        service_activity_count=service_activity_count,
        service_activity_table=service_activity_table,
        command_event_count=command_event_count,
        command_activity_rows=command_activity_rows,
        command_activity_table=command_activity_table,
        protocol_table=protocol_table,
        event_type_table=event_type_table,
        ip_rows=ip_rows,
        country_rows=country_rows,
        country_table=country_table,
        username_rows=username_rows,
        credential_registry_count=credential_registry_count,
        credential_alert_count=credential_alert_count,
        credential_alert_rows=credential_alert_rows,
        credential_alert_table=credential_alert_table,
        cluster_rows=cluster_rows,
        cluster_analyzed_at=cluster_analyzed_at,
        tracked_hash_count=tracked_hash_count,
        ti_count=ti_count,
        ti_rows=ti_rows,
        ti_table=ti_table,
        artifact_rows=artifact_rows,
        artifact_table=artifact_table,
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    end_day = now.strftime("%Y-%m-%d")
    if args.tag:
        filename_prefix = f"{args.tag}_report_ending_{end_day}"
    elif args.days == 7:
        filename_prefix = f"weekly_report_ending_{end_day}"
    else:
        filename_prefix = f"{args.days}-day_report_ending_{end_day}"
    html_path = OUT_DIR / f"{filename_prefix}.html"
    html_path.write_text(html, encoding="utf-8")
    print(f"HTML report created: {html_path}")

    try:
        from weasyprint import HTML
        pdf_path = html_path.with_suffix(".pdf")
        HTML(string=html, base_url=str(ROOT)).write_pdf(str(pdf_path))
        print(f"PDF report created: {pdf_path}")
    except ImportError:
        print("PDF not created: WeasyPrint is not installed.")
        print("The HTML report is ready; we'll configure PDF rendering next.")
    except Exception as exc:
        print(f"PDF generation failed: {exc}")
        print("The HTML report was still created successfully.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
