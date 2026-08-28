#!/bin/bash
# Scenario: reading an SSH host private key.
#   MITRE ATT&CK: T1552.004 (Private Keys)
#   ks-expect: ssh_private_key_read
#   ks-run: host
#
# Host, not lab: the watch is on the host's /etc/ssh. Read-only. sshd loads
# these once at startup, so anything else reading them is far more diagnostic
# than a /etc/shadow read -- hence the higher score.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 90; }

key="$(ls /etc/ssh/ssh_host_*_key 2>/dev/null | head -1 || true)"
[[ -n "$key" ]] || { echo "no SSH host key on this machine" >&2; exit 90; }

cat "$key" > /dev/null
echo "[scenario] read $key"
echo "[scenario] ssh_private_key_read complete"
