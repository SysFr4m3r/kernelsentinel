#!/bin/bash
# Scenario: a container executing in the host's mount namespace.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: namespace_escape
#   ks-run: host
#
# nsenter into PID 1's mount namespace is the "I have escaped" moment: the
# process still belongs to the container's cgroup, but it can see the host's
# filesystem. Detection is scoped to the mount namespace precisely because
# --net=host and --pid=host are ordinary configuration and this is not.
#
# Read-only: it enters the namespace and runs /bin/true. Nothing is modified.
set -euo pipefail
command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }

docker run --rm --privileged --pid=host debian:trixie-slim \
	nsenter --target 1 --mount -- /bin/true
echo "[scenario] namespace_escape complete"
