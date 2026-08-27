#!/bin/bash
# Noise: starting and stopping an ordinary container.
#   ks-expect: silence
#   ks-run: host
#
# The most likely source of false positives in this whole suite. Docker starting
# a container legitimately loads kernel modules (veth, nf_conntrack_netlink),
# talks to the runtime socket, and runs runc through several namespace
# transitions -- all of which resemble things the engine watches for. If routine
# container work alerts, the container detections are unusable in production.
#
# STATE-DEPENDENT, and the output says which state it ran in. Docker only loads
# veth and nf_conntrack_netlink the *first* time a container starts after boot;
# once resident, later runs reload nothing. So a pass here on a warm host does
# not mean a cold one is quiet -- on a freshly booted machine those loads
# produce module_load at score 50, squarely at the alerting floor. Reporting
# "silent" without saying which path was exercised would overstate the result.
set -euo pipefail
command -v docker >/dev/null || { echo "docker required" >&2; exit 90; }

# KS_COLD=1 unloads them first so the cold path can be exercised without
# waiting for a reboot. Opt-in, because unloading a kernel module on someone's
# machine is a real action -- and refused outright if anything is using them,
# since "Used by 0" is the only safe case.
if [[ "${KS_COLD:-}" == "1" ]]; then
	for m in veth nf_conntrack_netlink; do
		users="$(awk -v m="$m" '$1==m {print $3}' /proc/modules)"
		if [[ -n "$users" && "$users" != "0" ]]; then
			echo "[noise] $m in use ($users) -- refusing to unload" >&2
			exit 90
		fi
		grep -q "^$m " /proc/modules && { modprobe -r "$m" 2>/dev/null || true; }
	done
fi

resident=""
for m in veth nf_conntrack_netlink; do
	grep -q "^$m " /proc/modules && resident="$resident $m"
done
if [[ -n "$resident" ]]; then
	echo "[noise] already resident:$resident -- cold-boot module load path NOT exercised"
	echo "[noise] re-run with KS_COLD=1 to unload them first and test it properly"
else
	echo "[noise] modules not resident -- this run DOES exercise the cold-boot path"
fi

docker run --rm alpine true
echo "[noise] container_lifecycle complete"
