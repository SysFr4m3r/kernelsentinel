#!/bin/bash
# Scenario: grant file capabilities to a binary (SUID-equivalent backdoor with
# no SUID bit). Requires CAP_SETFCAP -- run with: KS_CAPS=SETFCAP
#   MITRE ATT&CK: T1548 (Abuse Elevation Control Mechanism)
#   Expected: EV_SETCAP on the target file.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2; exit 90
fi
target=/tmp/.capd
cp /bin/true "$target"
setcap cap_setuid+ep "$target"
getcap "$target"
echo "[scenario] file capabilities set on $target"
rm -f "$target"
