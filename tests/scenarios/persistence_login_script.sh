#!/bin/bash
# Scenario: a script that runs for every login shell.
#   MITRE ATT&CK: T1546.004 (Unix Shell Configuration Modification)
#   ks-expect: persistence_write
#   ks-run: host
#
# /etc/profile.d is sourced by every interactive login shell, so a file here
# runs as whoever logs in -- root included. It is among the mechanisms
# docs/DETECTIONS.md records as unwatched, alongside shell rc files.
#
# The file is inert: it declares a variable and nothing else.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write /etc/profile.d" >&2; exit 90; }
[[ -d "/etc/profile.d" ]] || { echo "/etc/profile.d not present on this host" >&2; exit 90; }

target="/etc/profile.d/ks-noise-probe.sh"
cleanup() { rm -f "$target"; }
trap cleanup EXIT
rm -f "$target"

printf '%s\n' 'KS_NOISE_PROBE=1' > "$target"
chmod "644" "$target"

echo "[scenario] persistence_login_script: wrote $target"
