#!/bin/bash
# Scenario: reading the credential store through a second name for it.
#   MITRE ATT&CK: T1003.008 (/etc/passwd and /etc/shadow)
#   ks-expect: credential_store_read
#   ks-run: host
#
# The read watch is a path prefix matched in-kernel against the path the file
# was opened by. docs/DETECTIONS.md records the consequence: "Reading a
# credential file through a hard link, a bind mount, or a copy made earlier is
# not matched, since the watch is still on the path."
#
# A hard link is the cheapest version -- one command, no mount namespace, and
# the inode is literally the same file. If the watch cannot see it, an attacker
# with root reads every hash on the host and the detection built for exactly
# that never fires.
#
# The link is made under /root because /tmp is tmpfs here and a hard link cannot
# cross filesystems. It is removed on exit; the credential store itself is only
# ever read.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to read /etc/shadow" >&2; exit 90; }
[[ -r /etc/shadow ]] || { echo "/etc/shadow not readable" >&2; exit 90; }

link=/root/.ks-shadow-link
cleanup() { rm -f "$link"; }
trap cleanup EXIT
rm -f "$link"

if ! ln /etc/shadow "$link" 2>/dev/null; then
	echo "cannot hard-link /etc/shadow to $link (different filesystem?)" >&2
	exit 90
fi
[[ "$(stat -c %i /etc/shadow)" == "$(stat -c %i "$link")" ]] \
	|| { echo "setup failed: $link is not the same inode" >&2; exit 1; }

cat "$link" > /dev/null

echo "[scenario] credential_read_hardlink: read inode $(stat -c %i "$link") via $link"
echo "[scenario] same file as /etc/shadow, reached by a name the watch does not list"
