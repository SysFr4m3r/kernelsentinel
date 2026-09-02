#!/bin/bash
# Scenario: landing a SUID root binary without ever calling chmod.
#   MITRE ATT&CK: T1548.001 (Setuid and Setgid)
#   ks-expect: suid_create
#   ks-run: host
#
# suid_create watches `path_chmod` for a 0 -> S_ISUID transition, so it sees the
# textbook `cp /bin/sh /tmp/.x && chmod u+s /tmp/.x`. docs/DETECTIONS.md records
# the other half as a known evasion: a file that is *already* SUID when it
# appears never transitions, so nothing fires.
#
# This is that evasion, run for real. `cp -p` preserves the mode of a
# root-owned SUID binary, so /tmp/.ks-suid-preserved arrives at 4755 with its
# owner intact and a working setuid-root shell behind it -- the same end state
# as the attack the detection does catch, reached by a route it may not watch.
#
# The point is to find out which. If this fails, the evasion is real and the
# detection has a hole an attacker reaches with one ordinary command.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to preserve a SUID root mode" >&2; exit 90; }

target=/tmp/.ks-suid-preserved
cleanup() { rm -f "$target"; }
trap cleanup EXIT
rm -f "$target"

# -p preserves mode and ownership: no chmod, no chown, one syscall path.
cp -p /usr/bin/su "$target"

[[ -u "$target" ]] || { echo "setup failed: $target is not SUID" >&2; exit 1; }
owner="$(stat -c '%U %a' "$target")"
echo "[scenario] suid_create_preserved: $target is $owner, created without chmod"
