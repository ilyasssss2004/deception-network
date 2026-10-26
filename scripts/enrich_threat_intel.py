#!/usr/bin/env python3
"""Enrich only indicators observed in the honeypot event database."""

import argparse
import base64
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "data" / "deception.sqlite3"
ENV_PATH = ROOT / ".env"
CACHE_TTL = timedelta(hours=24)
VT_LAST_REQUEST = None

FILE_EVENTS = (
    "cowrie.session.file_download",
    "cowrie.session.file_upload",
)
RESERVED_SUFFIXES = (
    ".localhost", ".local", ".lan", ".internal",
    ".test", ".example", ".invalid", ".home",
)


def secret(name):
    value = os.environ.get(name, "").strip()
    if value:
        return value

    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == name:
                return value.strip().strip('"').strip("'")
    return None


def get_json(url, headers, provider):
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "deception-network-lab/1.0",
            **headers,
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            return "ok", json.load(response)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except ValueError:
            payload = {}

        if exc.code == 404 and provider in ("GreyNoise", "VirusTotal"):
            return "not_found", {
                "message": "No matching record was found."
            }

        errors = payload.get("errors", [])
        detail = "; ".join(
            str(item.get("detail", "API error"))
            for item in errors if isinstance(item, dict)
        )
        detail = detail or payload.get("message", "")
        raise RuntimeError(
            f"{provider} HTTP {exc.code}"
            + (f": {detail}" if detail else "")
        ) from None
    except URLError as exc:
        raise RuntimeError(
            f"{provider} network error: {exc.reason}"
        ) from None
    except (TimeoutError, OSError) as exc:
        raise RuntimeError(f"{provider} request failed: {exc}") from None
    except ValueError:
        raise RuntimeError(f"{provider} returned invalid JSON") from None


def vt_get(path):
    global VT_LAST_REQUEST

    key = secret("VIRUSTOTAL_API_KEY")
    if not key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is missing from .env")

    # VirusTotal public API allowance: keep requests at least 16 seconds apart.
    if VT_LAST_REQUEST is not None:
        wait = 16 - (time.monotonic() - VT_LAST_REQUEST)
        if wait > 0:
            print(f"Respecting VirusTotal rate limit ({wait:.1f}s).",
                  flush=True)
            time.sleep(wait)

    VT_LAST_REQUEST = time.monotonic()
    return get_json(
        "https://www.virustotal.com/api/v3/" + path,
        {"x-apikey": key},
        "VirusTotal",
    )


def query_abuseipdb(ip):
    key = secret("ABUSEIPDB_API_KEY")
    if not key:
        raise RuntimeError("ABUSEIPDB_API_KEY is missing from .env")

    params = urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    status, payload = get_json(
        "https://api.abuseipdb.com/api/v2/check?" + params,
        {"Key": key},
        "AbuseIPDB",
    )
    data = payload.get("data", {})
    if not isinstance(data, dict):
        raise RuntimeError("AbuseIPDB response has no data object")

    return status, {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "distinct_reporters": data.get("numDistinctUsers"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "last_reported_at": data.get("lastReportedAt"),
    }


def query_greynoise(ip):
    # Prefer authenticated Community API access when configured.
    # The API key is never logged or included in the request URL.
    headers = {}
    key = secret("GREYNOISE_API_KEY")
    if key:
        headers["key"] = key

    status, payload = get_json(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers,
        "GreyNoise",
    )
    if status == "not_found":
        return status, payload

    return status, {
        "noise": payload.get("noise"),
        "riot": payload.get("riot"),
        "classification": payload.get("classification"),
        "name": payload.get("name"),
        "last_seen": payload.get("last_seen"),
        "message": payload.get("message"),
    }


def vt_attributes(path):
    status, payload = vt_get(path)
    if status == "not_found":
        return status, payload

    attrs = payload.get("data", {}).get("attributes", {})
    if not isinstance(attrs, dict) or not attrs:
        raise RuntimeError("VirusTotal response has no attributes")
    return status, attrs


def query_vt_ip(ip):
    status, attrs = vt_attributes(f"ip_addresses/{ip}")
    if status == "not_found":
        return status, attrs

    stats = attrs.get("last_analysis_stats") or {}
    return status, {
        "reputation": attrs.get("reputation"),
        "analysis_stats": stats,
        "country": attrs.get("country"),
        "as_owner": attrs.get("as_owner"),
        "network": attrs.get("network"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def query_vt_file(file_hash):
    status, attrs = vt_attributes(f"files/{file_hash}")
    if status == "not_found":
        return status, attrs

    return status, {
        "reputation": attrs.get("reputation"),
        "analysis_stats": attrs.get("last_analysis_stats") or {},
        "meaningful_name": attrs.get("meaningful_name"),
        "type_description": attrs.get("type_description"),
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def query_vt_domain(domain):
    status, attrs = vt_attributes(f"domains/{domain}")
    if status == "not_found":
        return status, attrs

    return status, {
        "reputation": attrs.get("reputation"),
        "analysis_stats": attrs.get("last_analysis_stats") or {},
        "categories": attrs.get("categories") or {},
        "last_analysis_date": attrs.get("last_analysis_date"),
        "registrar": attrs.get("registrar"),
    }


def query_vt_url(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    status, attrs = vt_attributes(f"urls/{url_id}")
    if status == "not_found":
        return status, attrs

    return status, {
        "reputation": attrs.get("reputation"),
        "analysis_stats": attrs.get("last_analysis_stats") or {},
        "categories": attrs.get("categories") or {},
        "last_analysis_date": attrs.get("last_analysis_date"),
        "title": attrs.get("title"),
    }


def valid_public_hostname(host):
    host = host.rstrip(".").lower()
    if not host or host == "localhost":
        return False

    if host.endswith(RESERVED_SUFFIXES):
        return False

    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        # This is a conservative syntax filter, not DNS verification.
        return "." in host and " " not in host


def collect_indicators(db):
    indicators = {
        "ip": [],
        "file_hash": [],
        "url": [],
        "domain": [],
    }

    for raw_ip, count in db.execute("""
        SELECT src_ip, COUNT(*)
        FROM events
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY COUNT(*) DESC
    """):
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            print("Skipping invalid source-IP value.")
            continue

        if not address.is_global:
            print(f"Skipping non-public source IP: {raw_ip}")
            continue

        indicators["ip"].append((str(address), count))

    # Only file-transfer event types can supply file hashes to VT.
    for file_hash, count in db.execute("""
        SELECT shasum, COUNT(*)
        FROM events
        WHERE eventid IN (?, ?)
          AND shasum IS NOT NULL AND shasum != ''
        GROUP BY shasum
        ORDER BY COUNT(*) DESC
    """, FILE_EVENTS):
        file_hash = file_hash.strip().lower()
        if re.fullmatch(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})",
                        file_hash):
            indicators["file_hash"].append((file_hash, count))
        else:
            print("Skipping invalid hash from a file-transfer event.")

    urls = Counter()
    domains = Counter()

    for raw_url, count in db.execute("""
        SELECT url, COUNT(*)
        FROM events
        WHERE url IS NOT NULL AND url != ''
        GROUP BY url
        ORDER BY COUNT(*) DESC
    """):
        raw_url = raw_url.strip()
        try:
            parts = urlsplit(raw_url)
            host = parts.hostname
            # Do not submit paths, credentials, tokens, or fragments.
            if (
                parts.scheme.lower() not in ("http", "https")
                or not host
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or len(raw_url) > 2048
                or not valid_public_hostname(host)
            ):
                print("Skipping URL that is incomplete, private, or unsafe to share.")
                continue
            # Force validation of any explicit port.
            _ = parts.port
        except ValueError:
            print("Skipping malformed URL indicator.")
            continue

        urls[raw_url] += count
        try:
            ipaddress.ip_address(host)
        except ValueError:
            domains[host.lower().rstrip(".")] += count

    indicators["url"] = sorted(
        urls.items(), key=lambda item: item[1], reverse=True
    )
    indicators["domain"] = sorted(
        domains.items(), key=lambda item: item[1], reverse=True
    )
    return indicators


def create_results_table(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_results (
            indicator_type TEXT NOT NULL,
            indicator TEXT NOT NULL,
            provider TEXT NOT NULL,
            status TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            summary_json TEXT NOT NULL,
            PRIMARY KEY (indicator_type, indicator, provider)
        )
    """)
    db.commit()


def cached_result(db, kind, indicator, provider):
    row = db.execute("""
        SELECT status, checked_at, summary_json
        FROM threat_intel_results
        WHERE indicator_type = ? AND indicator = ? AND provider = ?
    """, (kind, indicator, provider)).fetchone()

    if not row:
        return None

    try:
        checked = datetime.fromisoformat(row[1])
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    if datetime.now(timezone.utc) - checked >= CACHE_TTL:
        return None

    return row[0], json.loads(row[2]), row[1]


def save_result(db, kind, indicator, provider, status, count, summary):
    checked = datetime.now(timezone.utc).isoformat(timespec="seconds")
    db.execute("""
        INSERT INTO threat_intel_results
        (indicator_type, indicator, provider, status,
         checked_at, event_count, summary_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator_type, indicator, provider) DO UPDATE SET
            status = excluded.status,
            checked_at = excluded.checked_at,
            event_count = excluded.event_count,
            summary_json = excluded.summary_json
    """, (
        kind, indicator, provider, status, checked, count,
        json.dumps(summary, sort_keys=True),
    ))
    db.commit()


def process(db, kind, indicator, count, provider, lookup):
    cached = cached_result(db, kind, indicator, provider)
    display_indicator = indicator
    if kind == "url":
        display_indicator = urlsplit(indicator).hostname + " (URL hidden)"

    print(f"\n[{kind}] {display_indicator} | {provider} | events={count}")

    if cached:
        status, summary, checked = cached
        print(f"Using cached result from {checked}")
    else:
        try:
            status, summary = lookup(indicator)
            save_result(
                db, kind, indicator, provider, status, count, summary
            )
        except RuntimeError as exc:
            print(f"Lookup failed: {exc}")
            return False

    if status == "not_found":
        print("No record found by this provider.")
    else:
        # Print summarized fields, never full API responses or raw URLs.
        print(json.dumps(summary, indent=2, sort_keys=True))

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Enrich only indicators found in actual honeypot events."
    )
    parser.add_argument(
        "--max-items", type=int, default=10,
        help="Maximum unique indicators per type (default: 10)."
    )
    args = parser.parse_args()

    if args.max_items < 1:
        parser.error("--max-items must be at least 1")
    if not DB_PATH.exists():
        print(f"ERROR: Database not found: {DB_PATH}")
        return 1

    failed = False

    with sqlite3.connect(DB_PATH) as db:
        create_results_table(db)
        indicators = collect_indicators(db)

        print("\n=== OBSERVED INDICATOR COUNTS ===")
        for kind, items in indicators.items():
            print(f"{kind}: {len(items)} eligible unique indicators")

        ip_items = indicators["ip"][:args.max_items]
        for ip, count in ip_items:
            for provider, lookup in (
                ("AbuseIPDB", query_abuseipdb),
                ("GreyNoise", query_greynoise),
                ("VirusTotal", query_vt_ip),
            ):
                if not process(db, "ip", ip, count, provider, lookup):
                    failed = True

        for file_hash, count in indicators["file_hash"][:args.max_items]:
            if not process(
                db, "file_hash", file_hash, count,
                "VirusTotal", query_vt_file
            ):
                failed = True

        for url, count in indicators["url"][:args.max_items]:
            if not process(
                db, "url", url, count, "VirusTotal", query_vt_url
            ):
                failed = True

        for domain, count in indicators["domain"][:args.max_items]:
            if not process(
                db, "domain", domain, count,
                "VirusTotal", query_vt_domain
            ):
                failed = True

        print("\n=== FINISHED ===")
        print("Results table: threat_intel_results")
        print("Only indicators extracted from events were eligible.")
        if not ip_items and not indicators["file_hash"] \
                and not indicators["url"] and not indicators["domain"]:
            print("No eligible indicators: no API lookups were made.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
