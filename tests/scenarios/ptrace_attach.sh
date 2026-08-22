#!/bin/bash
# Scenario: ptrace another process (classic code-injection / debugging primitive).
#   MITRE ATT&CK: T1055.008 (Ptrace System Calls)
#   Expected: EV_PTRACE[ATTACH] -> the target pid.
set -euo pipefail
if [[ ! -f /.ks-lab ]] || [[ "${KS_LAB:-}" != "1" ]]; then
	echo "refusing to run outside the kernelsentinel lab container" >&2; exit 90
fi
python3 - <<'PY'
import ctypes, os, signal, time
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH = 16
pid = os.fork()
if pid == 0:
    signal.pause()          # child: just wait to be traced
    os._exit(0)
time.sleep(0.2)
r = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)   # attaching to own child: allowed under yama
print(f"[scenario] PTRACE_ATTACH to {pid} returned {r}")
os.waitpid(pid, 0)
libc.ptrace(17, pid, 0, 0)  # PTRACE_DETACH
os.kill(pid, signal.SIGKILL)
PY
