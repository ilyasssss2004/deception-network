# Deception Network

A containerized cybersecurity lab using multiple honeypots to capture
network interactions, normalize their events, and prepare for automated
threat intelligence and behavioral analysis.

## Implemented and tested

- **Cowrie SSH:** SSH login attempts and simulated shell activity.
- **OpenCanary HTTP:** HTTP interactions with a decoy web interface.
- **OpenCanary FTP:** FTP login attempts and connection events.
- **Python ingestion:** Normalizes Cowrie and OpenCanary JSON events.
- **SQLite:** Stores normalized events with duplicate detection.
- **Isolation:** Host-only service bindings and Docker egress restrictions.

## Planned

- Telnet honeypot testing.
- SMB deception and audit-log integration.
- AbuseIPDB, VirusTotal, and optional GreyNoise enrichment.
- Credential and file-hash alerts.
- Behavioral clustering and automated HTML/PDF reports.

Threat intelligence, clustering, and automated reporting are not yet
implemented. This repository is a work in progress.

## Lab architecture

The tested Ubuntu VM uses the host-only address `192.168.56.10`.
Current published endpoints are:

| Service | Endpoint |
|---|---|
| Cowrie SSH | `192.168.56.10:2222` |
| OpenCanary HTTP | `192.168.56.10:8080` |
| OpenCanary FTP | `192.168.56.10:21` |

The Docker honeypot bridge uses subnet `172.30.10.0/24`.

## Safety and privacy

This lab is intended for controlled, authorized testing. Do not expose
the services publicly without a separate security review.

Raw Cowrie and OpenCanary logs may contain attempted passwords and
other attacker-supplied data. Local logs, runtime configurations,
credentials, SQLite databases, and virtual environments must never
be committed to this repository.

The ingestion database omits plaintext password values. This does
not mean the raw honeypot logs are free of credentials.

## Main files

- `compose.yaml` — Cowrie and OpenCanary services.
- `scripts/ingest_cowrie.py` — multi-source event ingestion.
- `scripts/configure_opencanary.py` — local OpenCanary configuration.
- `scripts/deception-firewall.sh` — firewall isolation rules.
- `systemd/` — startup service definitions.
- `requirements.txt` — Python dependencies.

## Ingest events

After configuring the local runtime files and starting the honeypots:

```bash
python3 scripts/ingest_cowrie.py
```

The local database and raw event logs are deliberately excluded from Git.
