# Deception Network

A containerized cybersecurity lab for collecting and analyzing suspicious
activity through multiple honeypot services, with automated threat-intelligence
enrichment and behavioral analysis planned as subsequent stages.

## Implemented and tested

- **Cowrie:** SSH and Telnet honeypots with simulated shell interactions.
- **OpenCanary:** HTTP and FTP decoys, plus SMB audit monitoring.
- **Samba:** Authenticated, read-only SMB decoy share containing fictional files.
- **Audit pipeline:** Samba `full_audit` events forwarded through rsyslog
  to OpenCanary's SMB module.
- **Python and SQLite:** Event normalization, password-field sanitization,
  and duplicate detection across Cowrie and OpenCanary events.
- **Isolation:** Host-only service bindings and Docker egress restrictions.

## Lab architecture and endpoints

The Ubuntu VM uses the VirtualBox host-only address `192.168.56.10`.

| Service | Endpoint |
|---|---|
| Cowrie SSH | `192.168.56.10:2222` |
| Cowrie Telnet | `192.168.56.10:2223` |
| OpenCanary HTTP | `192.168.56.10:8080` |
| OpenCanary FTP | `192.168.56.10:21` |
| Samba SMB decoy | `192.168.56.10:445` |

Cowrie and OpenCanary run in Docker. Samba runs as a host service and shares
only fictional files from `/srv/deception-smb/decoyshare`.

Samba audit events are forwarded through rsyslog to
`/var/log/samba-audit.log`. OpenCanary reads this file through a read-only
container mount and generates SMB audit events.

The Docker honeypot bridge uses subnet `172.30.10.0/24`.

## Event ingestion

Run the multi-source event ingestion pipeline:

```bash
python3 scripts/ingest_cowrie.py
Events are normalized and stored in data/deception.sqlite3 with duplicate
detection. SMB events are classified as opencanary.smb.audit. Plaintext
password values are not stored in the database.
Threat intelligence and analysis roadmap
Planned features include:
- Automated enrichment through AbuseIPDB, VirusTotal, and GreyNoise.
- Behavioral clustering of recurring sessions and TTP patterns.
- Alerts for notable or previously unseen indicators.
- Automated weekly HTML/PDF threat reports and geographic visualizations.
Threat-intelligence enrichment, behavioral clustering, automated alerting,
and report generation are not yet implemented.
Safety and privacy
This lab is intended for controlled, authorized testing. Keep honeypot
services restricted to the host-only lab interface unless a separate
security review is performed.

Raw honeypot logs may contain attempted passwords or other attacker-supplied
data. Local runtime configurations, credentials, SQLite databases, and raw
logs must not be committed to Git.

The files under config/ are reproducible example templates. Review
host-specific settings and back up existing system configurations before
applying them.
Main files
- compose.yaml — Cowrie and OpenCanary containers.
- scripts/ingest_cowrie.py — multi-source event ingestion.
- scripts/configure_opencanary.py — local OpenCanary configuration.
- scripts/deception-firewall.sh — Docker isolation rules.
- config/samba/smb.conf.example — Samba decoy configuration template.
- config/rsyslog/30-samba-audit.conf — Samba audit forwarding rule.
- systemd/ — Docker startup service definitions.
- requirements.txt — Python dependencies.
The local database, runtime configuration, credentials, and raw event logs
are deliberately excluded from Git.
