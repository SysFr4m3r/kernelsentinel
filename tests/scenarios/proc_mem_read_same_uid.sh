#!/bin/bash
# Scenario: reading another process's memory at the same privilege level.
#   MITRE ATT&CK: T1003 (OS Credential Dumping), T1055.008 (Ptrace Injection)
#   ks-expect: ptrace_attach
#   ks-run: host
#
# The ptrace sensor drops same-uid, read-only access in-kernel -- that filter is
# what keeps ps, top and systemd from flooding the daemon. docs/DETECTIONS.md
# records the resulting gap and then claims a mitigation: /proc/<pid>/mem is
# still caught, because opening it takes PTRACE_MODE_ATTACH credentials rather
# than read credentials.
#
# That claim had never been run. If it is wrong, root reading another root
# process's memory is invisible, which is credential dumping with no signal.
#
# The target is a sleep this scenario starts and kills. One page is read and
# discarded; nothing is written and no other process is touched.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to read another process's memory" >&2; exit 90; }

sleep 30 &
target=$!
cleanup() { kill "$target" 2>/dev/null || true; }
trap cleanup EXIT
# Give the child a moment to be scheduled and its maps to exist.
for _ in $(seq 1 20); do
	[[ -r "/proc/$target/maps" ]] && break
	sleep 0.1
done

python3 - "$target" <<'PY'
import sys
pid = int(sys.argv[1])
# First mapped region, read through /proc/<pid>/mem: the path that takes
# ATTACH-mode credentials even for a plain read.
with open(f"/proc/{pid}/maps") as m:
    start, end = m.readline().split()[0].split("-")
start, end = int(start, 16), int(end, 16)
with open(f"/proc/{pid}/mem", "rb", 0) as mem:
    mem.seek(start)
    data = mem.read(min(4096, end - start))
print(f"read {len(data)} bytes from pid {pid}", file=sys.stderr)
PY

echo "[scenario] proc_mem_read_same_uid: read memory of pid $target"
