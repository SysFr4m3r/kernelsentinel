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

resident=""
for m in veth nf_conntrack_netlink; do
	grep -q "^$m " /proc/modules && resident="$resident $m"
done
if [[ -n "$resident" ]]; then
	echo "[noise] already resident:$resident -- the cold-boot module load path is NOT exercised"
else
	echo "[noise] modules not resident -- this run exercises the cold-boot path"
fi

docker run --rm alpine true
echo "[noise] container_lifecycle complete"
