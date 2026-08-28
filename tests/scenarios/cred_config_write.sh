#!/bin/bash
# Scenario: sudoers tampering.
#   MITRE ATT&CK: T1098
#   ks-expect: cred_config_write
#   ks-run: lab
#
# Writes inside the container's own filesystem, so the path the kernel reports
# is the watched one. Contained entirely -- nothing outside the container
# changes, and the lab image pre-creates these directories so a missing one
# cannot make this pass by writing nothing.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi

target=/etc/sudoers.d/ks-scenario
mkdir -p "$(dirname "$target")"
printf '# kernelsentinel scenario\n' >> "$target"
[[ -s "$target" ]] || { echo "setup failed: $target empty" >&2; exit 1; }
echo "[scenario] wrote $target"
echo "[scenario] cred_config_write complete"
