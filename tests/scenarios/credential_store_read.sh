#!/bin/bash
# Scenario: reading the credential store from something that is not an
# authentication program.
#   MITRE ATT&CK: T1003.008 (/etc/passwd and /etc/shadow)
#   ks-expect: credential_store_read
#   ks-run: host
#
# Host, not lab: /etc/shadow inside the container is the container's own file,
# not the host's, and the read watch is on the host's. Read-only -- it reads one
# file and discards it.
#
# `cat` is used deliberately: the detector suppresses the programs whose job is
# authentication (unix_chkpwd, sshd, sudo, su), so a scenario using one of those
# would correctly produce nothing.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to read /etc/shadow" >&2; exit 90; }
[[ -r /etc/shadow ]] || { echo "/etc/shadow not readable" >&2; exit 90; }

cat /etc/shadow > /dev/null
echo "[scenario] credential_store_read complete"
