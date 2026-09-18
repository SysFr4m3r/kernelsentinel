#!/bin/bash
# Scenario: container escape by writing the host's core_pattern through a
# bind-mounted /proc.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: kernel_escape_hatch_write
#   ks-run: host
#
# This is the attack that defeated the first version of the detection: the
# container mounts the host's /proc somewhere else, so the kernel reports a path
# no watchlist entry matches. Detection must key on file identity, not path.
#
# Runs on the HOST (it is a docker invocation), not inside the lab container.
# Needs a working docker daemon.
set -euo pipefail

command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }

before="$(cat /proc/sys/kernel/core_pattern)"
restore() {
	# Never leave the host's core_pattern pointing anywhere but where it was.
	# If enforcement blocked the write this is a no-op; if it did not, this is
	# the difference between a test and a persistence primitive.
	local now
	now="$(cat /proc/sys/kernel/core_pattern)"
	if [[ "$now" != "$before" ]]; then
		echo "[scenario] restoring core_pattern (was modified: $now)" >&2
		echo "$before" > /proc/sys/kernel/core_pattern
	fi
}
trap restore EXIT

echo "[scenario] core_pattern before: $before"

# The outcome is asserted, not tolerated. This used to print SUCCEEDED or
# BLOCKED and pass either way, which meant the suite could not tell armed
# enforcement from enforcement that silently does nothing -- the only thing the
# feature exists to do.
rc=0
docker run --rm --privileged -v /proc:/hostproc alpine \
	sh -c 'echo "|/tmp/ks-scenario" > /hostproc/sys/kernel/core_pattern' || rc=$?

if [[ "${KS_ENFORCE:-off}" == "on" ]]; then
	[[ $rc -ne 0 ]] || {
		echo "NOT BLOCKED: enforcement is armed and the container escape succeeded" >&2
		exit 1
	}
	now="$(cat /proc/sys/kernel/core_pattern)"
	[[ "$now" == "$before" ]] || {
		echo "enforcement returned an error but the write landed anyway ($now)" >&2
		exit 1
	}
	echo "[scenario] write BLOCKED and core_pattern unchanged"
else
	[[ $rc -eq 0 ]] || {
		echo "write failed with enforcement off (rc=$rc); the escape was never" >&2
		echo "actually performed, so nothing was tested" >&2
		exit 1
	}
	echo "[scenario] write SUCCEEDED (expected without --enforce on)"
fi

echo "[scenario] container_escape_corepattern complete"
