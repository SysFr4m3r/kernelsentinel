#!/bin/bash
# Scenario: new SUID root binary in a world-writable dir, then executed.
#   MITRE ATT&CK: T1548.001 (Setuid and Setgid)
#   ks-expect: suid_create
#   ks-run: lab
#   Expected detection: EV_FILE_MODE, SUID gained, path /tmp/.x, parent chain
#                       back to this shell.
#
# Destructive-ish (creates a SUID binary). Guarded to the lab container.
set -euo pipefail

if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	echo "use: tests/lab/run.sh run 'bash /scenarios/suid_create.sh'" >&2
	exit 90
fi

target=/tmp/.x
cp /bin/sh "$target"

# Assert the write landed. A scenario that silently does nothing must not look
# like a pass -- the whole point is that a *missing* detection means the sensor
# missed, never that the attack never happened.
[[ -f "$target" ]] || { echo "setup failed: $target not created" >&2; exit 1; }

chmod u+s "$target"

# Confirm the SUID bit is actually set before we claim to have triggered it.
[[ -u "$target" ]] || { echo "setup failed: SUID bit not set" >&2; exit 1; }
echo "[scenario] SUID bit set on $target:"
ls -l "$target"

# Execute it -- a created-and-run SUID binary is a stronger signal than one that
# just sits there.
"$target" -c 'id' || true

rm -f "$target"
echo "[scenario] suid_create complete"
