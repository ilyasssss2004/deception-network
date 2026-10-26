# Deception Network
### Multi-Service Honeypot Grid with Automated Threat Intelligence Enrichment

A containerized cybersecurity lab that captures suspicious interactions through
multiple honeypot services, normalizes telemetry into SQLite, analyzes session
behavior, tracks credential and file-hash indicators, enriches eligible
indicators with external threat intelligence, and generates scheduled
HTML/PDF security reports.

The project represents a focused **deception and detection component within a
larger Security Operations Center (SOC)**. It is not intended to replace an
enterprise SIEM, endpoint detection platform, firewall, or complete SOC.

---

## Table of Contents

- [1. Project Overview](#1-project-overview)
- [2. Architecture](#2-architecture)
- [3. Technologies](#3-technologies)
- [4. Honeypots and Protocol Coverage](#4-honeypots-and-protocol-coverage)
- [5. Event Collection and Data Pipeline](#5-event-collection-and-data-pipeline)
- [6. Behavioral Analysis and Detection](#6-behavioral-analysis-and-detection)
- [7. Threat Intelligence Enrichment](#7-threat-intelligence-enrichment)
- [8. File Capture and Hash Analysis](#8-file-capture-and-hash-analysis)
- [9. Automated Alerting](#9-automated-alerting)
- [10. Security Reports](#10-security-reports)
- [11. Automation and Scheduling](#11-automation-and-scheduling)
- [12. Installation and Configuration](#12-installation-and-configuration)
- [13. Operating the Pipeline](#13-operating-the-pipeline)
- [14. Database Structure](#14-database-structure)
- [15. Security, Isolation and Privacy](#15-security-isolation-and-privacy)
- [16. SOC and SIEM Integration Context](#16-soc-and-siem-integration-context)
- [17. Current Limitations](#17-current-limitations)
- [18. Troubleshooting](#18-troubleshooting)
- [19. Project Structure](#19-project-structure)

---

## 1. Project Overview

### Objectives

The project is designed to:

1. Deploy multiple honeypot services in a controlled VirtualBox lab.
2. Capture suspicious interactions, authentication activity, commands,
   connection metadata, and file-transfer events where supported.
3. Normalize telemetry from Cowrie and OpenCanary into a local SQLite database.
4. Deduplicate events and avoid storing plaintext passwords in the normalized
   event database.
5. Group Cowrie sessions using command patterns and behavioral similarity.
6. Track previously unseen credential pairs using keyed HMAC fingerprints.
7. Record and alert on new SHA-256 hashes observed in supported file transfers.
8. Enrich eligible observed indicators through AbuseIPDB, GreyNoise Community,
   and VirusTotal.
9. Generate concise, analyst-oriented HTML/PDF reports on a schedule.
10. Maintain a reproducible, isolated environment suitable for cybersecurity
    learning, demonstrations, and portfolio development.

### Design principles

- **Observed evidence first:** intelligence lookups are based on indicators
  collected by the honeypots, rather than arbitrary reference indicators.
- **Defense in depth:** host-only networking, firewall rules and a read-only
  SMB share reduce unnecessary exposure.
- **Data minimization:** normalized credential records use keyed fingerprints;
  report output excludes plaintext passwords.
- **Repeatable processing:** ingestion uses event hashes to ignore duplicates.
- **Separation of duties:** capture, analysis, enrichment and report generation
  are separate processing stages.
- **Evidence-based reporting:** unavailable provider data or missing telemetry
  is reported as such rather than inferred.

---

## 2. Architecture

The lab runs on an Ubuntu virtual machine hosted in VirtualBox. The current
host-only interface uses `192.168.56.10`.

```text
                   Authorized lab clients
                            |
                    VirtualBox host-only
                            |
                     Ubuntu host VM
                     192.168.56.10
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
       Cowrie           OpenCanary           Samba
       Docker             Docker            host service
          |                 |                  |
          |                 |             Read-only share
          |                 |             + Samba audit
          |                 |                  |
          |                 +<---- rsyslog -----+
          |                       audit events
          |
          +------------------+------------------+
                             |
                             v
                    Python ingestion pipeline
                             |
                             v
                     SQLite event database
                     data/deception.sqlite3
                             |
              +--------------+---------------+
              |              |               |
              v              v               v
       Session analysis   Credential       File-hash
         and TTP tags      tracking         tracking
              |              |               |
              +--------------+---------------+
                             |
                             v
                    Threat intelligence
               AbuseIPDB / GreyNoise / VirusTotal
                             |
                             v
                      SQLite enrichment
                             |
                             v
                   HTML and PDF reporting
```

The components run locally. The host-only interface is intended for controlled
lab interactions and is not a public deployment endpoint.

### Network endpoints

The current lab uses these host-only service bindings:

| Service | Host endpoint | Purpose |
|---|---|---|
| Cowrie SSH | `192.168.56.10:2222` | SSH interaction and supported file-transfer capture |
| Cowrie Telnet | `192.168.56.10:2223` | Telnet sessions and simulated command activity |
| OpenCanary HTTP | `192.168.56.10:8080` | HTTP decoy and request telemetry |
| OpenCanary FTP | `192.168.56.10:21` | FTP decoy and authentication telemetry |
| Samba SMB share | `192.168.56.10:445` | Read-only decoy share with access auditing |

The Docker honeypot bridge uses subnet `172.30.10.0/24`.

Cowrie and OpenCanary run in Docker. Samba runs as a host service and shares
fictional files from `/srv/deception-smb/decoyshare`.

Samba audit events are forwarded through rsyslog to `/var/log/samba-audit.log`.
OpenCanary reads this file through its configured read-only mount and generates
SMB audit events.

Actual container addresses may change when containers are recreated. Use the
configured host endpoints for lab access instead of relying on container IPs.

---

## 3. Technologies

| Technology | Role in the project |
|---|---|
| Ubuntu Linux | Host operating system for the lab |
| VirtualBox | Isolated virtual-machine environment |
| Docker and Docker Compose | Run Cowrie and OpenCanary services |
| Cowrie | SSH/Telnet honeypot with session, command and supported file-transfer telemetry |
| OpenCanary | Low-interaction service decoys and alert generation |
| Samba | Authenticated, read-only SMB decoy share |
| rsyslog | Forward Samba audit events to the configured audit log |
| Samba `full_audit` | Records configured SMB share operations |
| iptables and `DOCKER-USER` | Restrict traffic involving the Docker honeypot subnet |
| Python 3 | Event normalization, analysis, enrichment, alert tracking and reporting |
| SQLite | Persistent event and analysis database |
| Requests | HTTP API requests to threat-intelligence providers |
| Jinja2 | HTML report template rendering |
| WeasyPrint | PDF generation from the HTML report |
| systemd services and timers | Schedule recurring processing jobs |

The project deliberately uses a local SQLite database for its current scale.
A production SOC may use a centralized SIEM, data lake, or event broker instead.

---

## 4. Honeypots and Protocol Coverage

### 4.1 Cowrie: SSH and Telnet

Cowrie is a medium-interaction SSH/Telnet honeypot. It provides emulated shell
interactions and structured session telemetry.

The current configuration records relevant events such as:

- Session connections and closures.
- Client metadata and protocol negotiation events.
- Successful and failed login attempts.
- Commands entered and failed command attempts.
- Session identifiers and event timestamps.
- File uploads and supported file-download events, including hashes when
  available from the event metadata.

**SSH file transfers:** Cowrie can record supported SCP/SFTP uploads. Its
emulated shell can also generate download events for supported operations.

**Telnet:** Telnet sessions and command inputs are captured. SCP/SFTP are SSH
protocols, not Telnet transfer mechanisms. Supported emulated download
commands may generate file-download events.

Commands entered into Cowrie's emulated shell are not intended to run as
arbitrary commands on the Ubuntu host.

### 4.2 OpenCanary: HTTP and FTP

OpenCanary provides low-interaction service decoys.

The current deployment captures service-specific events, including:

- HTTP requests, such as recorded GET requests and requested paths.
- FTP login-attempt events.
- Available source addresses, ports, event timestamps and service messages.

These modules are used for telemetry and detection. They are **not configured
as general-purpose malware-upload collection services**.

### 4.3 Samba SMB decoy share

Samba runs as a host service and exports an authenticated, read-only share
containing fictional decoy files.

The current share is associated with:

```text
/srv/deception-smb/decoyshare
```

Samba `full_audit` records configured access operations. rsyslog forwards
these events to `/var/log/samba-audit.log`, and OpenCanary's SMB audit
integration converts them into structured SMB audit events for ingestion.

Recorded activity may include:

- Share access and disconnection.
- File open/close operations.
- Share and file metadata operations.
- Operation status, where present in the audit message.

The share is intentionally read-only. SMB write attempts are not a supported
file-capture mechanism in this deployment.

### Protocol capability summary

| Service | Interaction logging | Command telemetry | File capture |
|---|---|---|---|
| Cowrie SSH | Yes | Yes | Supported SCP/SFTP uploads and supported downloads |
| Cowrie Telnet | Yes | Yes | Supported emulated downloads, when captured |
| OpenCanary HTTP | Request events | No shell commands | No general-purpose upload capture |
| OpenCanary FTP | Authentication/service events | No shell commands | No general-purpose upload capture |
| Samba SMB | Share audit events | No shell commands | Read-only share; uploads are denied |

The report describes only capabilities and activity actually observed. It
does not infer file capture for HTTP, FTP or SMB when no such capture path
exists.

---

## 5. Event Collection and Data Pipeline

### Ingestion

The main ingestion script is:

```bash
python3 scripts/ingest_cowrie.py
```

It reads the configured Cowrie and OpenCanary JSON event logs, normalizes
supported events, and inserts them into SQLite.

The event database is:

```text
data/deception.sqlite3
```

The `events` table includes fields such as:

- `event_hash`
- `timestamp`
- `eventid`
- `source`
- `sensor`
- `src_ip` and `dst_ip`
- `src_port` and `dst_port`
- `session`
- `protocol`
- `username`
- `input`
- `url`
- `shasum`
- `message`

Fields can be null when the source service does not supply the corresponding
data. For example, OpenCanary SMB audit events may not have a session ID or
source port.

### Deduplication

The normalized `events` table uses `event_hash` as its primary key. Ingestion
uses `INSERT OR IGNORE`, so repeatedly reading the same raw logs does not
insert duplicate copies of the same normalized event.

The current ingester reads the configured log files on each run and relies on
event-hash deduplication for repeat safety.

### Password handling

The normalized SQLite event schema is designed not to retain plaintext
passwords. The credential tracking script reads credential-bearing log events
in memory and stores a keyed HMAC fingerprint plus safe metadata.

Raw honeypot logs may still contain attempted credentials. Raw logs therefore
remain local and must be protected with restrictive filesystem permissions.

---

## 6. Behavioral Analysis and Detection

### Session clustering

`scripts/cluster_sessions.py` analyzes Cowrie sessions with recorded session
identifiers.

It derives summaries such as:

- Session start and end times.
- Event and command counts.
- Login successes and failures.
- Command-family classifications.
- Behavioral/TTP tags.
- Heuristic cluster identifiers.

The derived results are stored in `session_analysis`.

The session-analysis table is rebuilt from the current source events when the
script runs. It is derived data; the script does not delete the underlying
`events` table.

Clustering uses command-family and sequence similarity heuristics. A shared
cluster is **not proof** that sessions came from the same attacker or campaign.

### Credential-pair tracking

`scripts/credential_alerts.py` detects newly observed credential pairs using
keyed HMAC fingerprints generated from the configured `CREDENTIAL_HMAC_KEY`.

The `credential_pairs` table tracks distinct fingerprints and associated safe
metadata such as first-seen time, source, protocol, username and event type.
The plaintext password is not written to this table.

A new credential pair can generate an alert. The dedicated
`credential_alert_history` table records persistent alert metadata for new
alerts since that history mechanism was introduced. Historical console alerts
from before its creation are not automatically backfilled.

### File-hash tracking

`scripts/hash_alerts.py` tracks valid SHA-256 hashes derived from completed
Cowrie file-transfer events.

It does not execute captured files. Hash detection is based on the captured
event metadata and the configured tracking state.

---

## 7. Threat Intelligence Enrichment

The enrichment script is:

```bash
python3 scripts/enrich_threat_intel.py --max-items 10
```

It processes eligible indicators extracted from observed honeypot events and
stores provider results in `threat_intel_results`.

### Providers and endpoints

| Provider | Purpose | Current lookup model |
|---|---|---|
| AbuseIPDB | IP abuse reputation and reporting context | Individual observed public-IP check |
| GreyNoise Community | Internet-scanner and IP context | Individual observed public-IP Community API lookup |
| VirusTotal | IP, file-hash, URL and domain intelligence where supported | Indicator lookups using the VirusTotal API |

The current implementation uses AbuseIPDB's individual IP check endpoint, not
its full blacklist feed. GreyNoise uses the individual Community endpoint,
not a downloaded complete list of scanners.

The project intentionally enriches observed indicators instead of importing
unrelated reference indicators into the operational dataset.

### Indicator eligibility

The enrichment code:

- Skips IP addresses that are not globally routable.
- Uses SHA-256 hashes from observed Cowrie file-transfer events.
- Restricts URL/domain lookups to indicators passing the code's validation
  and public-target checks.
- Uses cached results to avoid unnecessary repeated provider requests.
- Applies a delay between VirusTotal requests to respect its configured
  request pacing.

The default `--max-items 10` limits processing to up to ten unique indicators
per indicator type in one invocation. This is a per-run processing limit, not
a guarantee that every possible indicator will be enriched immediately.
Review the limit and provider quotas when increasing ingestion volume.

### API configuration

The private `.env` file may contain:

```dotenv
ABUSEIPDB_API_KEY=replace_with_your_key
GREYNOISE_API_KEY=
VIRUSTOTAL_API_KEY=replace_with_your_key
CREDENTIAL_HMAC_KEY=replace_with_a_random_secret
```

- `ABUSEIPDB_API_KEY`: used for AbuseIPDB requests.
- `GREYNOISE_API_KEY`: optional for the current GreyNoise Community API
  implementation; authenticated access may be available depending on account
  eligibility and provider terms.
- `VIRUSTOTAL_API_KEY`: used for VirusTotal requests.
- `CREDENTIAL_HMAC_KEY`: secret key used to create credential fingerprints.

Protect `.env` with restrictive permissions and never commit it to Git.

Generate a random HMAC key locally, for example:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Use the generated value in your private `.env` file. Do not paste API keys or
the HMAC key into chat, issue trackers, reports or source control.

A provider returning no record is not the same as a provider request failing.
The stored provider status and summary should be interpreted alongside the
report's observation data and the provider's own API limits.

### Validation status and interpretation

The lab has successfully exercised the VirusTotal file-hash path using the
hash of the harmless EICAR antivirus test pattern.

That test demonstrates that a captured hash can be matched to a provider
result. It does **not** demonstrate a real malware infection.

The live AbuseIPDB and GreyNoise IP-enrichment paths require eligible observed
public IPs and successful API responses before their operation can be
considered verified in this lab.

---

## 8. File Capture and Hash Analysis

The current file-capture path is based on Cowrie's supported upload/download
events.

For captured file transfers, the project can record:

- Filename, when provided.
- Transfer event and timestamp.
- Session identifier, when available.
- SHA-256 hash, when provided by the event.
- VirusTotal hash analysis, when a result is available.

The enrichment workflow queries file hashes rather than uploading captured
file contents to VirusTotal.

No malware samples are executed on the Ubuntu host. Captured files and
runtime artifacts should remain isolated and must not be committed to Git.

### EICAR validation

EICAR is a harmless antivirus test pattern designed to test antivirus
handling. A high number of provider detections for its hash is not evidence
of a real malware infection.

Keep the EICAR validation report separate from routine operational reporting
when presenting project results. Label the test explicitly as validation
evidence.

---

## 9. Automated Alerting

The current alert mechanisms include:

- Newly observed credential-pair fingerprints.
- Newly tracked SHA-256 file hashes.
- Provider results stored for eligible observed indicators.
- Behavioral/session summaries for analyst review.

Credential tracking is persistent in `credential_pairs`. New credential alert
metadata is stored in `credential_alert_history`.

File-hash tracking is stored in `artifact_hash_alerts`, with supporting state
in `artifact_alert_state`.

An alert in this project is a detection signal for review, not an automatic
proof of compromise. The lab does not automatically execute captured files or
block an IP based solely on a reputation lookup.

---

## 10. Security Reports

The report generator is:

```bash
python3 scripts/generate_report.py --days 7
```

The report includes an analyst-oriented summary of the selected reporting
window.

### Report contents

The current template includes:

1. Executive summary and headline metrics.
2. Event-source and protocol statistics.
3. Activity grouped by honeypot and protocol.
4. Source-IP observations and classification.
5. Geographic context when provider-supplied country data is available.
6. Authentication activity and username statistics.
7. Behavioral analysis and session clusters.
8. Representative Cowrie command activity.
9. Representative OpenCanary HTTP, FTP and SMB service activity.
10. Captured Cowrie file-transfer hashes and available VirusTotal findings.
11. Eligible threat-intelligence results.
12. Persistent credential-alert history and stated limitations.

The report is a **summary, not a raw log export**. Raw event detail remains
in the SQLite database for investigation. Command previews are sanitized on a
best-effort basis, so generated reports must remain private and be reviewed
before sharing.

The report does not infer attacker geography from private IP addresses.
Country information, when available, is identified as provider-supplied
context rather than independently verified physical location.

### Report output

Reports are written under:

```text
reports/private/
```

Typical filenames include:

```text
weekly_report_ending_YYYY-MM-DD.html
weekly_report_ending_YYYY-MM-DD.pdf
```

Tagged validation reports use a separate filename:

```bash
python3 scripts/generate_report.py --days 7 --tag validation
```

The `--days` argument controls the reporting window. A quiet week may contain
few or no events; the report summarizes what was observed during the selected
period, rather than fabricating expected activity.

The `reports/private/` directory is intentionally ignored by Git.

---

## 11. Automation and Scheduling

The running lab uses three systemd timers.

| Job | Current schedule | Responsibilities |
|---|---|---|
| `deception-pipeline.timer` | Every 2 minutes | Ingestion, session analysis, credential detection and file-hash tracking |
| `deception-enrichment.timer` | Every 30 minutes | Enrichment of eligible observed indicators |
| `deception-weekly-report.timer` | Monday at 00:10 UTC | Generate the seven-day HTML/PDF report |

The jobs are `Type=oneshot` services: they start, perform their work and exit.
An `inactive (dead)` state after a successful oneshot run is normal. The
corresponding timer should remain active.

The wrappers use a shared lock to reduce concurrent execution, write monthly
automation logs under `logs/automation/`, and return a nonzero status on
failure.

Example manual invocations:

```bash
./scripts/run_pipeline.sh
./scripts/run_enrichment.sh
./scripts/run_report.sh --days 7
```

### Deployment reproducibility

The three automation services and their timers are version-controlled under
`systemd/`. On the configured lab VM, these files have been compared with the
installed definitions and validated with `systemd-analyze verify`.

For a fresh installation, review the service files first. They currently use
the project path `/home/vboxuser/deception-network` and the account `vboxuser`.
Adjust these values if the target VM uses a different account or directory.

After configuring the honeypots, Python dependencies, `.env`, database and
report dependencies, install the automation units from the repository:

```bash
sudo cp systemd/deception-pipeline.service systemd/deception-pipeline.timer systemd/deception-enrichment.service systemd/deception-enrichment.timer systemd/deception-weekly-report.service systemd/deception-weekly-report.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemd-analyze verify /etc/systemd/system/deception-pipeline.service /etc/systemd/system/deception-pipeline.timer /etc/systemd/system/deception-enrichment.service /etc/systemd/system/deception-enrichment.timer /etc/systemd/system/deception-weekly-report.service /etc/systemd/system/deception-weekly-report.timer
```

Review the configuration before enabling the timers on a new host. To enable
the schedule after validation:

```bash
sudo systemctl enable --now deception-pipeline.timer deception-enrichment.timer deception-weekly-report.timer
```

Cloning the repository does not automatically install or enable systemd
services. The VM and the required honeypot services and log sources must be
running for activity collection and scheduled processing to occur.

---

## 12. Installation and Configuration

This section describes the software and configuration needed by the processing
scripts. Recreating the entire virtual network also requires configuring
Docker, Cowrie, OpenCanary, Samba, rsyslog and the host firewall.

### Prerequisites

- Ubuntu Linux virtual machine.
- VirtualBox host-only network configured for the lab.
- Docker and Docker Compose.
- Cowrie and OpenCanary containers configured as described above.
- Samba and rsyslog configured for the SMB audit path.
- Python 3, SQLite, the dependencies in `requirements.txt`, and WeasyPrint
  for PDF generation.
- API credentials for providers you intend to use.
- A private HMAC key for credential tracking.

### Python dependencies

Install the Python packages using the Python environment appropriate for the
host. On systems that restrict system-wide `pip` installation, use a virtual
environment for development.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

PDF generation also requires a working WeasyPrint installation and its
platform dependencies. Validate PDF generation on the target Ubuntu system
before relying on the scheduled report service.

The currently installed systemd services use the system's `python3`
executable. If using a virtual environment for scheduled execution, update
the service configuration to use that environment consistently.

### Secrets

Create and protect `.env` locally. Configure the provider keys you have and a
strong random `CREDENTIAL_HMAC_KEY`.

```bash
chmod 600 .env
```

Check that `.env` is ignored by Git before staging changes.

### Check the database

After successful ingestion, inspect the database:

```bash
sqlite3 data/deception.sqlite3 ".tables"
```

Inspect event counts without showing sensitive command or credential data:

```bash
sqlite3 -header -column data/deception.sqlite3 "
SELECT source, protocol, eventid, COUNT(*) AS events
FROM events
GROUP BY source, protocol, eventid
ORDER BY source, protocol, events DESC;
"
```

---

## 13. Operating the Pipeline

### Run ingestion and local detections

```bash
./scripts/run_pipeline.sh
```

The wrapper runs the following in order:

1. `scripts/ingest_cowrie.py`
2. `scripts/cluster_sessions.py`
3. `scripts/credential_alerts.py`
4. `scripts/hash_alerts.py`

### Run threat-intelligence enrichment

```bash
./scripts/run_enrichment.sh
```

The default wrapper uses `--max-items 10`. The script processes eligible
indicators found in the dataset and respects its provider cache and request
pacing.

### Generate a seven-day report

```bash
./scripts/run_report.sh --days 7
```

Generate a separate validation report:

```bash
./scripts/run_report.sh --days 7 --tag validation
```

### Check timer status

```bash
systemctl list-timers --all \
  deception-pipeline.timer \
  deception-enrichment.timer \
  deception-weekly-report.timer
```

Check the most recent service result:

```bash
systemctl --no-pager --full status deception-pipeline.service
systemctl --no-pager --full status deception-enrichment.service
systemctl --no-pager --full status deception-weekly-report.service
```

Read recent service logs:

```bash
sudo journalctl \
  -u deception-pipeline.service \
  -u deception-enrichment.service \
  -u deception-weekly-report.service \
  --since "1 hour ago" --no-pager
```

The wrapper logs are also stored locally under `logs/automation/`.

---

## 14. Database Structure

The following tables are used by the current processing workflow. Some are
created or populated by the corresponding script when that stage runs.

| Table | Purpose |
|---|---|
| `events` | Normalized Cowrie and OpenCanary telemetry |
| `session_analysis` | Derived Cowrie session summaries, tags and cluster assignments |
| `credential_pairs` | HMAC fingerprints of distinct credential pairs and safe metadata |
| `credential_alert_history` | Persistent metadata for new credential alerts |
| `artifact_hash_alerts` | File hashes tracked by the alerting stage |
| `artifact_alert_state` | State used by the file-hash tracker |
| `threat_intel_results` | Provider lookup status, cached responses and summarized results |

The database is local runtime data. It is excluded from Git because it may
contain private lab telemetry and investigation artifacts.

The tables serve different purposes: an event records what was observed, a
derived table summarizes or classifies observations, and an alert-history table
records detections generated by the alerting logic.

---

## 15. Security, Isolation and Privacy

This project is intended for controlled, authorized testing.

### Network restrictions

- Keep honeypot services bound to the host-only lab interface.
- Do not expose these services to the public Internet without a separate
  security review and an appropriate isolation strategy.
- Preserve the Docker egress restrictions and host filtering rules.
- The Samba decoy share must remain read-only unless the architecture is
  deliberately redesigned and reviewed.
- Do not disable host protections to make a test easier.

### Credential protection

- Do not commit `.env` or share API keys.
- Use a strong random HMAC key for credential fingerprints.
- Keep raw Cowrie and OpenCanary logs private; attempted credentials may appear
  in raw logs even though the normalized database avoids storing passwords.
- Do not include plaintext passwords or full secret-bearing commands in reports.

### File handling

- Do not execute captured files on the host.
- Hash analysis and reputation lookups should not be treated as permission to
  open or execute a suspicious file.
- Keep captured files and private reports out of Git.
- EICAR is a harmless test pattern; label its results as validation evidence.

### Git hygiene

The repository intentionally excludes runtime and private data such as:

- `.env`
- SQLite database files and backups
- Raw event logs
- Captured runtime files
- Private HTML/PDF reports
- Automation logs
- Python bytecode and virtual-environment files

Verify staged changes before every commit:

```bash
git status --short
git diff --cached --check
git diff --cached --name-only
```

---

## 16. SOC and SIEM Integration Context

This project is one potential telemetry source within a broader SOC workflow.

An enterprise SOC may already collect events from endpoints, identity services,
network devices, firewalls, cloud platforms and servers. The Deception Network
adds context about interactions with deliberately exposed decoy services.

Its outputs can support:

- Investigation of suspicious source IPs.
- Analysis of authentication attempts and command patterns.
- Discovery of file hashes associated with observed sessions.
- Enrichment of indicators with external reputation information.
- Identification of recurring behavioral patterns.
- Triage through analyst-oriented reports.

The current implementation stores its events and findings locally in SQLite.
It is not itself a complete SIEM and does not yet establish a production-grade
central event-forwarding integration. A future integration could forward
selected normalized events and persistent alerts to a SIEM using an approved
ingestion interface, while preserving timestamps, provenance and source
protocol information.

Provider reputation alone should not determine whether an event is malicious.
Correlate it with the observed behavior, service context and other available
evidence.

---

## 17. Current Limitations

The project is a functioning lab pipeline, but several limitations should
remain explicit.

1. **Private lab sources:** host-only testing commonly produces private or
   local source addresses. Those are correctly excluded from public IP
   reputation lookups.
2. **Provider availability:** a lookup can be rate-limited, unavailable,
   inconclusive or return no record. A missing result is not a benign verdict.
3. **Enrichment batch cap:** the default limit is ten unique indicators per
   type per invocation; larger collections may require tuning and backlog
   handling.
4. **GreyNoise authentication:** the current code supports an optional
   `GREYNOISE_API_KEY`. The live IP-lookup path still needs a successful
   response against an eligible observed public IP to be considered verified
   in this lab.
5. **File capture:** file capture is supported through Cowrie transfer events;
   the current OpenCanary HTTP/FTP decoys and read-only SMB share are not
   general-purpose malware-collection services.
6. **Session clustering:** similarity groups are heuristic and do not prove
   common attribution.
7. **Credential alert history:** the persistent history table records new
   alerts from the point it was introduced. Earlier console alerts are not
   automatically backfilled.
8. **Systemd packaging:** the running VM has its automation timers enabled.
   Their unit definitions must be kept as version-controlled repository files
   to make deployment to a fresh clone reproducible.
9. **Report redaction:** command redaction is best-effort. Private reports
   must be reviewed before external sharing.
10. **Not a full SOC/SIEM:** centralized telemetry, case management, escalation
    and production response orchestration are outside the current scope.

---

## 18. Troubleshooting

### The pipeline reports duplicate events

This is expected when the same raw logs are reprocessed. Event hashes and the
unique `event_hash` key prevent repeated inserts.

### A service has zero session IDs

Some sources, including the current OpenCanary event records, may not populate
session IDs. Report their event and source details without interpreting a
missing session identifier as missing activity.

### No public IPs are enriched

Check the observed source addresses first. Private, loopback and other
non-global addresses are intentionally skipped.

### A provider returns no result

Review the provider status, API configuration, API quota and eligible
indicator value. Do not infer a clean reputation result from a failed or
inconclusive request.

### The PDF is not generated

Confirm that WeasyPrint is installed and available to the same execution
environment used by the report service. The HTML report may still be created
even when PDF rendering fails.

### A systemd service completed but shows `inactive (dead)`

For a successful `Type=oneshot` job this is normal. Check its last exit status,
the corresponding timer, the journal and the wrapper log.

### The timer does not seem to run

Check whether the VM is running, the timer is enabled, the next run time is
correct, and the service has the required file and configuration access.

---

## 19. Project Structure

```text
deception-network/
├── compose.yaml
├── README.md
├── requirements.txt
├── .gitignore
├── config/
│   ├── samba/
│   └── rsyslog/
├── scripts/
│   ├── ingest_cowrie.py
│   ├── cluster_sessions.py
│   ├── credential_alerts.py
│   ├── hash_alerts.py
│   ├── enrich_threat_intel.py
│   ├── generate_report.py
│   ├── deception-firewall.sh
│   ├── run_pipeline.sh
│   ├── run_enrichment.sh
│   └── run_report.sh
├── systemd/
│   └── Existing deployment service definitions
├── data/
│   └── Local database, raw logs and runtime data (not committed)
├── logs/
│   └── Local automation logs (not committed)
└── reports/
    └── private/
        └── Locally generated reports (not committed)
```

The exact configuration files and log paths depend on the active host and
container setup. Inspect local configuration before applying changes to a
different machine.

---

## Project Status

The current implementation includes multi-service honeypot telemetry,
SQLite ingestion and deduplication, Cowrie session analysis, credential-pair
tracking, file-hash tracking, threat-intelligence enrichment code,
HTML/PDF reporting, and scheduled automation on the configured lab VM.

The systemd service and timer definitions are now version-controlled.
Remaining development priorities include validating each provider with
eligible observed indicators, strengthening enrichment backlog handling,
and improving centralized alert/report integration for a future SIEM.

**This project is an isolated deception-telemetry and analysis component for
SOC-oriented learning and portfolio demonstration.**
