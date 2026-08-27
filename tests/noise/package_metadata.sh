#!/bin/bash
# Noise: package manager activity.
#   ks-expect: silence
#   ks-run: host
#
# Deliberately metadata-only: `apt-get update` rather than an install. A real
# install is the more interesting case -- dpkg creates SUID binaries and writes
# systemd units, which is structurally identical to the attacks this tool
# detects -- but installing software on someone's machine to run a test is not a
# trade worth making. That case belongs in a disposable VM.
set -euo pipefail
command -v apt-get >/dev/null || { echo "apt-get required" >&2; exit 90; }
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 90; }
apt-get update -qq 2>/dev/null || true
echo "[noise] package_metadata complete"
