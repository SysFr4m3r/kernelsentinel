#!/bin/bash
# Scenario: reading another user's process environment -- the credential-theft
# shape, as opposed to reading your own.
#   MITRE ATT&CK: T1003, T1552
#   ks-expect: cross_uid_proc_read
#   ks-run: host
#
# Host, not lab: inside a container every process descends from PID 1, so a
# read always lands inside the reader's own lineage -- which the detector
# suppresses on purpose, because theft means reaching *outside* your tree. The
# target here is a system daemon that is not an ancestor of this shell.
#
# Read-only. It reads one file and discards it.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must start as root to drop privilege" >&2; exit 90; }
command -v setpriv >/dev/null || { echo "setpriv required (util-linux)" >&2; exit 90; }

# A root-owned daemon that is not in this process's ancestry.
target=""
for name in systemd-journald systemd-udevd dbus-daemon systemd-logind; do
	pid="$(pgrep -u root -x "$name" 2>/dev/null | head -1 || true)"
	[[ -n "$pid" ]] && { target="$pid"; echo "[scenario] target: $name ($pid)"; break; }
done
[[ -n "$target" ]] || { echo "no suitable root daemon found" >&2; exit 90; }

setpriv --reuid=1000 --regid=1000 --clear-groups \
	cat "/proc/$target/environ" >/dev/null 2>&1 || true
echo "[scenario] cross_uid_proc_read complete"
