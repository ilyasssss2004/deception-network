#!/usr/bin/env bash
set -euo pipefail

IPT=/usr/sbin/iptables
SUBNET=172.30.10.0/24

# Wait for Docker to create its user firewall chain.
for _ in $(seq 1 30); do
    if "$IPT" -w -S DOCKER-USER >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

"$IPT" -w -S DOCKER-USER >/dev/null 2>&1 || {
    echo "ERROR: Docker DOCKER-USER chain is unavailable." >&2
    exit 1
}

# Create our own chain, or rebuild it if it already exists.
"$IPT" -w -N DECEPTION-HONEYPOT 2>/dev/null || true
"$IPT" -w -F DECEPTION-HONEYPOT

# Permit replies to incoming sessions; block new outbound flows.
"$IPT" -w -A DECEPTION-HONEYPOT \
    -s "$SUBNET" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j RETURN

"$IPT" -w -A DECEPTION-HONEYPOT \
    -s "$SUBNET" -j DROP

# Leave traffic from other networks unaffected by this chain.
"$IPT" -w -A DECEPTION-HONEYPOT -j RETURN

# Remove previous manually added rules, if present.
while "$IPT" -w -C DOCKER-USER \
    -s "$SUBNET" -m conntrack --ctstate RELATED,ESTABLISHED \
    -j RETURN 2>/dev/null; do
    "$IPT" -w -D DOCKER-USER \
        -s "$SUBNET" -m conntrack --ctstate RELATED,ESTABLISHED \
        -j RETURN
done

while "$IPT" -w -C DOCKER-USER \
    -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
    -j RETURN 2>/dev/null; do
    "$IPT" -w -D DOCKER-USER \
        -s "$SUBNET" -m conntrack --ctstate ESTABLISHED,RELATED \
        -j RETURN
done

while "$IPT" -w -C DOCKER-USER \
    -s "$SUBNET" -j DROP 2>/dev/null; do
    "$IPT" -w -D DOCKER-USER -s "$SUBNET" -j DROP
done

# Ensure there is exactly one jump to our chain, placed first.
while "$IPT" -w -C DOCKER-USER \
    -j DECEPTION-HONEYPOT 2>/dev/null; do
    "$IPT" -w -D DOCKER-USER -j DECEPTION-HONEYPOT
done

"$IPT" -w -I DOCKER-USER 1 -j DECEPTION-HONEYPOT

# Prevent containers in this subnet from accessing host services.
if ! "$IPT" -w -C INPUT -s "$SUBNET" -j DROP 2>/dev/null; then
    "$IPT" -w -I INPUT 1 -s "$SUBNET" -j DROP
fi

echo "Deception Network firewall rules applied."
