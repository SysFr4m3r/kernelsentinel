#!/bin/bash
# Noise: a web application calling its own Python tooling.
#   ks-expect: silence
#   ks-run: lab
#
# interpreter_from_network_daemon was added this session with a documented
# false positive and no test for it: gunicorn and uwsgi *are* Python, the name
# half of the daemon match catches both, and a web application spawning a
# Python subprocess is routine work. That is a claim in a docs file, which is
# the exact thing this session has spent its time disproving.
#
# So it runs the claim. A process named gunicorn spawns python3 several times
# over, the way a worker shells out to its own tooling. The signal scores 25 and
# must not reach the MEDIUM floor -- on its own or by chaining with anything
# else this ordinary work produces.
#
# Contained: runs in the lab, touches /tmp only.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2
	exit 90
fi
command -v python3 >/dev/null || { echo "python3 required in the lab image" >&2; exit 90; }

# Not /tmp. A real gunicorn lives on the system path, and putting the fake one
# in /tmp adds exec_from_tmp (20) to every run -- a second family, which chains
# with the interpreter signal and scores 63. That would be the scenario's own
# staging producing the alert, not the behaviour it claims to test.
fake=/usr/local/bin/gunicorn
cp /bin/sh "$fake"
[[ -x "$fake" ]] || { echo "setup failed: $fake not executable" >&2; exit 1; }
cleanup() { rm -f "$fake"; }
trap cleanup EXIT

# A worker calling out to its own tooling, repeatedly -- the shape a real
# deployment produces all day.
for _ in 1 2 3 4 5; do
	"$fake" -c "python3 -c 'print(1)'" >/dev/null 2>&1 || true
done

echo "[noise] web_app_subprocess: gunicorn spawned python3 five times"
