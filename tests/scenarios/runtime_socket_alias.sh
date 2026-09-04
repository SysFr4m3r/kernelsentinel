#!/bin/bash
# Scenario: reaching the container runtime socket under a name it was not bound as.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: runtime_socket_access
#   ks-run: host
#
# The match is on the path string the *connecting* process supplies, which is
# the one thing an attacker chooses -- the same shape as the hard link to
# /etc/shadow that read every hash on the host without producing an event.
#
# A symlink is enough: path lookup follows it during connect, so the connection
# lands on the real runtime socket while the name the sensor sees is one the
# attacker invented. Nothing about docker's own configuration changes.
set -euo pipefail
command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }
[[ $EUID -eq 0 ]] || { echo "must run as root to reach the runtime socket" >&2; exit 90; }

sock=""
for candidate in /run/docker.sock /var/run/docker.sock; do
	[[ -S "$candidate" ]] && { sock="$candidate"; break; }
done
[[ -n "$sock" ]] || { echo "no docker socket on this host" >&2; exit 90; }

alias_path="/tmp/ks-runtime-alias.sock"
cleanup() { rm -f "$alias_path"; }
trap cleanup EXIT
rm -f "$alias_path"
ln -s "$sock" "$alias_path"

# Talk to the runtime through the invented name. A ping is the smallest real
# request the daemon answers; nothing is created, started or changed.
python3 - "$alias_path" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
reply = s.recv(64)
s.close()
if b"200" not in reply:
    print(f"runtime did not answer: {reply!r}", file=sys.stderr)
    sys.exit(1)
PY

echo "[scenario] runtime_socket_alias: reached $sock as $alias_path"
