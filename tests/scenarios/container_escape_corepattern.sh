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
# Expected to FAIL under --enforce on, and to succeed (but be detected) without.
docker run --rm --privileged -v /proc:/hostproc alpine \
	sh -c 'echo "|/tmp/ks-scenario" > /hostproc/sys/kernel/core_pattern' \
	&& echo "[scenario] write SUCCEEDED (expected without --enforce on)" \
	|| echo "[scenario] write BLOCKED (expected with --enforce on)"

echo "[scenario] container_escape_corepattern complete"
