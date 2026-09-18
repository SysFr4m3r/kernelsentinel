#!/bin/bash
# Scenario: a web-server process spawning an interpreter instead of a shell.
#   MITRE ATT&CK: T1059.006 (Python), T1059.004 (Unix Shell)
#   ks-expect: interpreter_from_network_daemon
#   ks-run: lab
#
# shell_from_network_daemon recognises the daemon two ways -- by the identity of
# its executable and by name -- but recognises the *child* one way only: a list
# of nine shell names. docs/DETECTIONS.md records that as an evasion, and it is
# the one gap in this audit that cannot be closed the way the others were.
# There is no kernel-side answer to "is this an interpreter": python3 is an
# ordinary binary that ordinary daemons ordinarily exec.
#
# The interpreter must not exec a shell. A Python reverse shell that calls
# pty.spawn("/bin/sh") is still caught -- the shell is a grandchild of the
# daemon and the ancestry walk finds it -- so writing the scenario that way
# would pass while the gap stayed open. A pure in-process implant execs nothing:
# it reads files and talks to its socket from inside the interpreter. That is
# what this runs, minus the socket.
#
# Mirrors shell_from_network_daemon.sh: the daemon is a copy of /bin/sh called
# nginx, exercising the name half of the ancestry match. Contained -- runs in
# the lab, reads one file, touches nothing.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi
command -v python3 >/dev/null || { echo "python3 required in the lab image" >&2; exit 90; }

fake=/tmp/nginx
cp /bin/sh "$fake"
[[ -x "$fake" ]] || { echo "setup failed: $fake not executable" >&2; exit 1; }

# nginx($fake) -> python3, and the interpreter execs nothing at all.
#
# No `exec` in front of python3. With it the shell replaces itself, so the
# process that runs the interpreter *is* the daemon rather than its child -- and
# after the exec its comm is python3, leaving no nginx anywhere in the ancestry
# to match. It is also not what the attack looks like: a daemon that execs an
# implant over itself has stopped being a daemon. Mirrors the structure of
# shell_from_network_daemon.sh exactly, which is the version known to work.
"$fake" -c "python3 -c 'open(\"/etc/passwd\").read()'" >/dev/null 2>&1 || true

rm -f "$fake"
echo "[scenario] interpreter_from_network_daemon complete"
