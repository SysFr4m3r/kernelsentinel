#!/bin/bash
# Scenario: execution from a world-writable, volatile directory.
#   MITRE ATT&CK: T1036 (Masquerading)
#   ks-expect: exec_from_tmp
#   ks-run: lab
#
# Low-scoring by design -- it earns weight only in a chain. The suite runs the
# agent at --min-severity info so a correctly-quiet signal is still observable.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi

target=/tmp/ks-payload
cp /bin/id "$target"
[[ -x "$target" ]] || { echo "setup failed: $target not executable" >&2; exit 1; }
"$target" >/dev/null
rm -f "$target"
echo "[scenario] exec_from_tmp complete"
