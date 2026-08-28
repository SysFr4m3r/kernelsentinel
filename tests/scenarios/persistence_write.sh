#!/bin/bash
# Scenario: persistence via a cron drop-in.
#   MITRE ATT&CK: T1053 (Scheduled Task/Job)
#   ks-expect: persistence_write
#   ks-run: lab
#
# Contained: writes inside the container's own /etc. The lab image pre-creates
# /etc/cron.d precisely so a missing directory cannot make this pass by writing
# nothing.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi

target=/etc/cron.d/ks-scenario
echo '* * * * * root /tmp/ks-payload' > "$target"
[[ -s "$target" ]] || { echo "setup failed: $target empty" >&2; exit 1; }
rm -f "$target"
echo "[scenario] persistence_write complete"
