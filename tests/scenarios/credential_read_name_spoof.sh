#!/bin/bash
# Scenario: evading the credential-read suppression by wearing its name.
#   MITRE ATT&CK: T1003.008 (/etc/passwd and /etc/shadow), T1036.005 (Masquerading)
#   ks-expect: credential_store_read
#   ks-run: host
#
# The detector suppresses the programs whose job is authentication, because
# every login on the host reads /etc/shadow and the signal would otherwise fire
# dozens of times a day. That suppression used to key on `comm`, which the
# process chooses: copying /bin/cat to /tmp/sudo made the read invisible.
#
# This is the regression test for closing that. Suppression now requires the
# reader's *executable* to be one of the host's real authentication binaries,
# matched by (device, inode) -- so /tmp/sudo is not sudo, and this must alert
# exactly as a read by `cat` does.
#
# Read-only: it copies a binary into /tmp, reads one file, discards both.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to read /etc/shadow" >&2; exit 90; }
[[ -r /etc/shadow ]] || { echo "/etc/shadow not readable" >&2; exit 90; }

spoof=/tmp/sudo
cp /bin/cat "$spoof"
[[ -x "$spoof" ]] || { echo "setup failed: $spoof not executable" >&2; exit 1; }

# comm is "sudo"; the executable is a copy of cat, with its own inode.
"$spoof" /etc/shadow > /dev/null

rm -f "$spoof"
echo "[scenario] credential_read_name_spoof complete"
