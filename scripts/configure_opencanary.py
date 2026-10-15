#!/usr/bin/env python3
"""Configure local OpenCanary HTTP and FTP services."""

import json
from pathlib import Path

project = Path(__file__).resolve().parents[1]
path = project / "data/opencanary-config/opencanary.conf"

if not path.is_file():
    raise SystemExit(
        f"Missing {path}. Generate the default config with --copyconfig first."
    )

config = json.loads(path.read_text())

# Disable every configured service, then enable only HTTP and FTP.
for key, value in list(config.items()):
    if key.endswith(".enabled") and isinstance(value, bool):
        config[key] = False

config.update({
    "device.node_id": "opencanary-http-lab",
    "http.enabled": True,
    "http.port": 8081,
    "ftp.enabled": True,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
})

# Keep OpenCanary's raw events in its protected persistent file only.
config["logger"] = {
    "class": "PyLogger",
    "kwargs": {
        "formatters": {
            "plain": {"format": "%(message)s"}
        },
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "filename": "/var/tmp/opencanary.log",
                "formatter": "plain",
            }
        },
    },
}

path.write_text(json.dumps(config, indent=2) + "\n")
path.chmod(0o640)

print("OpenCanary configured.")
print("Enabled services: HTTP, FTP")
print("Raw event logs remain local-only.")
