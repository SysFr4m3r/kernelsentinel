#!/bin/bash
# Noise: a service handed its connection as stdin, inetd-style.
#   ks-expect: silence
#   ks-run: lab
#
# This is the false positive that socket-backed stdio detection has to survive.
# inetd, xinetd and systemd units with `Accept=yes` all exec the service with
# the accepted connection already on fd 0/1/2 -- exactly the shape a reverse
# shell produces. The difference is what gets exec'd: a service binary, not an
# interactive shell.
#
# If this alerts, the detection is matching "socket on stdin" rather than
# "shell reading commands from a socket", and every socket-activated service on
# a host becomes an incident.
#
# Contained: --network none, loopback only.
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
    # The inetd contract: connection on fd 0/1/2, and the thing exec'd is
    # a service, not a shell. /bin/date is as inert as it gets.
    srv.close()
    s = socket.create_connection(("127.0.0.1", port))
    for fd in (0, 1, 2):
        os.dup2(s.fileno(), fd)
    os.execv("/bin/date", ["/bin/date"])

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

echo "[noise] inetd_style_service: exec'd /bin/date with the connection on stdin"
