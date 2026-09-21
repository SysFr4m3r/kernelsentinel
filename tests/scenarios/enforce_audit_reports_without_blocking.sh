#!/bin/bash
# Scenario: audit mode reports what it would block, and blocks nothing.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: kernel_escape_hatch_write
#   ks-detail: would be blocked
#   ks-run: host
#
# README.md tells an operator, in bold, to run audit first: "It reports every
# operation enforcement *would* have blocked, and blocks nothing, so you find
# out what breaks before it breaks." Two claims, and until now neither had a
# test. Both enforcement modes that *do* something were covered -- off and on --
# and the one recommended as the safe starting point was not.
#
# That is this project's most persistent bug species: a strong verb in
# operator-facing documentation with nothing checking it. Five were found in one
# sitting, none by a test.
#
# The two halves are asserted separately and both matter. If audit blocks, the
# advice to "run audit first" is actively dangerous. If audit stays silent, the
# operator learns nothing and arms enforcement blind.
set -euo pipefail
command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }

if [[ "${KS_ENFORCE:-off}" != "audit" ]]; then
	echo "needs KS_ENFORCE=audit; nothing to prove in any other mode" >&2
	exit 90
fi

before="$(cat /proc/sys/kernel/core_pattern)"
restore() {
	local now
	now="$(cat /proc/sys/kernel/core_pattern)"
	if [[ "$now" != "$before" ]]; then
		echo "$before" > /proc/sys/kernel/core_pattern
	fi
}
trap restore EXIT

# Half one: audit must not block. The write has to succeed.
rc=0
docker run --rm --privileged -v /proc:/hostproc alpine \
	sh -c 'echo "|/tmp/ks-scenario" > /hostproc/sys/kernel/core_pattern' || rc=$?

[[ $rc -eq 0 ]] || {
	echo "BLOCKED: audit mode denied a write it is documented never to deny" >&2
	echo "the advice to run audit before arming enforcement is unsafe if this fails" >&2
	exit 1
}

now="$(cat /proc/sys/kernel/core_pattern)"
[[ "$now" != "$before" ]] || {
	echo "the write reported success but core_pattern is unchanged; nothing was tested" >&2
	exit 1
}

# Half two -- that the incident says "would be blocked" -- is the ks-detail
# assertion above, checked by the harness against the agent's own output.
echo "[scenario] enforce_audit_reports_without_blocking: write allowed, core_pattern changed"
