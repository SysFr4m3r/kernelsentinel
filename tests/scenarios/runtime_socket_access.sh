#!/bin/bash
# Scenario: a process talking to the container runtime's control socket.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: runtime_socket_access
#   ks-run: host
#
# Runs on the HOST deliberately. The lab never mounts the real docker.sock --
# that mount *is* the escape being tested elsewhere, so it has no business being
# available to every scenario. On a host this is the low-scoring, baseline-able
# case: the docker CLI does it constantly.
set -euo pipefail
command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }
docker ps >/dev/null
echo "[scenario] runtime_socket_access complete"
