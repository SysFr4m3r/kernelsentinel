#!/bin/bash
# Scenario: fileless execution. Create an anonymous in-memory executable and
# run it via /proc/self/fd/N -- the binary never touches disk.
#   MITRE ATT&CK: T1620 (Reflective Code Loading)
#   ks-expect: fileless_exec
#   ks-run: lab
#   Expected: EV_EXEC_ANON, source=memfd.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2; exit 90
fi
python3 - <<'PY'
import os
fd = os.memfd_create("payload", 0)   # not CLOEXEC: must survive execve
with open("/bin/true", "rb") as f:
    os.write(fd, f.read())
pid = os.fork()
if pid == 0:
    # Detection must NOT rely on this /proc/self/fd path string -- the sensor
    # keys on the memfd: dentry name, which survives re-opening the fd.
    os.execv(f"/proc/self/fd/{fd}", ["payload"])
os.waitpid(pid, 0)
print("[scenario] executed from memfd")
PY
