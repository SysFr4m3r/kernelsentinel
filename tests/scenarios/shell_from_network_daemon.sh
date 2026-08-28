#!/bin/bash
# Scenario: a web-server process spawning a shell -- the webshell shape.
#   MITRE ATT&CK: T1059.004 (Unix Shell)
#   ks-expect: shell_from_network_daemon
#   ks-run: lab
#
# The detection matches a network daemon in the ancestry two ways: by the file
# identity of its executable, and by name. This scenario exercises the name
# half -- a copy of /bin/sh called nginx -- which is what still catches the
# shebang-script daemons (gunicorn, uwsgi) whose mapped executable is really the
# Python interpreter.
#
# The name half is safe here precisely because a match only ever *raises* a
# signal: a process falsely called nginx accuses itself. The mirror image, where
# a name could *suppress* a signal, is not allowed anywhere -- see
# credential_read_name_spoof.sh. The identity half is covered by
# a_daemon_is_recognised_by_identity_or_by_name_but_never_excused in
# tests/replay_fixtures.rs, which needs no container.
#
# sshd is deliberately excluded from the daemon table: spawning a login shell
# is its job.
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
