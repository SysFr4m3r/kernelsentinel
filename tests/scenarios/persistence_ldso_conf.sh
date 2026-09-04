#!/bin/bash
# Scenario: adding a library search path, the quieter half of a linker hijack.
#   MITRE ATT&CK: T1574.006 (Dynamic Linker Hijacking)
#   ks-expect: persistence_write
#   ks-run: host
#
# /etc/ld.so.preload is watched because it is unambiguous. /etc/ld.so.conf.d is
# not, and it reaches the same place: a directory added here is searched for
# every shared library on the host after ldconfig runs. Same attack family, one
# step less direct, and unwatched.
#
# The directory named does not exist, so nothing is actually preloaded.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write /etc/ld.so.conf.d" >&2; exit 90; }
[[ -d "/etc/ld.so.conf.d" ]] || { echo "/etc/ld.so.conf.d not present on this host" >&2; exit 90; }

target="/etc/ld.so.conf.d/ks-noise-probe.conf"
cleanup() { rm -f "$target"; }
trap cleanup EXIT
rm -f "$target"

printf '%s\n' '/nonexistent/kernelsentinel-scenario' > "$target"
chmod "644" "$target"

echo "[scenario] persistence_ldso_conf: wrote $target"
