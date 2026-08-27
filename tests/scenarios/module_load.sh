#!/bin/bash
# Scenario: loading a kernel module.
#   MITRE ATT&CK: T1547.006 (Kernel Modules and Extensions)
#   ks-expect: module_load
#   ks-run: host
#
# Host-only, and the lab Dockerfile says why: filesystem effects stay in a
# container, kernel effects do not. `dummy` is a standard, harmless network
# driver, and this refuses to run if it was already loaded so the cleanup can
# never unload something the host actually wanted.
set -euo pipefail
command -v modprobe >/dev/null || { echo "modprobe required" >&2; exit 90; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 90; }

mod=dummy
modinfo "$mod" >/dev/null 2>&1 || { echo "$mod module not available on this kernel" >&2; exit 90; }
grep -q "^$mod " /proc/modules && { echo "$mod already loaded -- refusing to touch it" >&2; exit 90; }

trap 'rmmod "$mod" 2>/dev/null || true' EXIT

# Surface modprobe's own complaint rather than a bare "not loaded". The previous
# version asserted with `lsmod | grep` and reported only that the check failed,
# which said nothing about why.
if ! out="$(modprobe -v "$mod" 2>&1)"; then
	echo "modprobe failed: $out" >&2
	exit 1
fi
[[ -n "$out" ]] && echo "[scenario] $out"

# /proc/modules is what lsmod reads, without the formatting. Give the kernel a
# moment: modprobe returns once the init call completes, but the entry can lag
# fractionally behind, and a race here looks exactly like a missed detection.
for _ in 1 2 3 4 5 6 7 8 9 10; do
	grep -q "^$mod " /proc/modules && break
	sleep 0.2
done
if ! grep -q "^$mod " /proc/modules; then
	echo "setup failed: $mod not present in /proc/modules after modprobe succeeded" >&2
	echo "  /proc/modules head: $(head -3 /proc/modules | tr '\n' '|')" >&2
	exit 1
fi

echo "[scenario] $mod loaded"
echo "[scenario] module_load complete"
