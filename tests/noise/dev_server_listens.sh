#!/bin/bash
# Noise: a developer running a local server.
#   ks-expect: silence
#   ks-run: lab
#
# unexpected_listener fires for anything opening a port that is not one of the
# host's known daemons, which on a development machine is constant and
# legitimate: a static file server, a test harness, a language server, a
# database someone started by hand. That is exactly why it scores 25 and sits
# below the alerting floor.
#
# If this alerts, the score is wrong and every developer's afternoon becomes an
# incident.
#
# Contained: --network none, loopback only.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi
command -v python3 >/dev/null || { echo "python3 required in the lab image" >&2; exit 90; }

# Several listeners, the way a working machine accumulates them.
python3 - <<'ENDPY'
import socket
socks = []
for _ in range(4):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(5)
    socks.append(s)
for s in socks:
    s.close()
ENDPY

echo "[noise] dev_server_listens: opened and closed four listening ports"
