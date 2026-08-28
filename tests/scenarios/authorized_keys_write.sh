#!/bin/bash
# Scenario: SSH key persistence.
#   MITRE ATT&CK: T1098.004
#   ks-expect: authorized_keys_write
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

target=/root/.ssh/authorized_keys
mkdir -p "$(dirname "$target")"
printf '# kernelsentinel scenario\n' >> "$target"
[[ -s "$target" ]] || { echo "setup failed: $target empty" >&2; exit 1; }
echo "[scenario] wrote $target"
echo "[scenario] authorized_keys_write complete"
