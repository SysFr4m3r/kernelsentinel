#!/bin/bash
# Scenario: a web-server process spawning a shell -- the webshell shape.
#   MITRE ATT&CK: T1059.004 (Unix Shell)
#   ks-expect: shell_from_network_daemon
#   ks-run: lab
#
# The detection keys on the *ancestry* carrying a network daemon's name, so a
# shell renamed to nginx reproduces the shape faithfully: what matters is that a
# process called nginx spawned a shell, which is exactly what a command
# injection looks like from the kernel's side. sshd is deliberately excluded
# from that list, because spawning a login shell is its job.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi

fake=/tmp/nginx
cp /bin/sh "$fake"
[[ -x "$fake" ]] || { echo "setup failed: $fake not executable" >&2; exit 1; }

# nginx($fake) -> sh -> id
"$fake" -c '/bin/sh -c id' >/dev/null 2>&1 || true

rm -f "$fake"
echo "[scenario] shell_from_network_daemon complete"
