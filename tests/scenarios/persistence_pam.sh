#!/bin/bash
# Scenario: adding a PAM module, which is authentication itself.
#   MITRE ATT&CK: T1543 (Create or Modify System Process), T1556 (Modify Authentication Process)
#   ks-expect: cred_config_write
#   ks-run: host
#
# /etc/pam.d is where authentication is configured. A line here can accept any
# password, or run a program on every login, and it takes effect without
# restarting anything. docs/DETECTIONS.md lists "a PAM config" among the
# persistence mechanisms the fixed watch list does not cover.
#
# Writes a single file this suite owns and removes it; the real PAM stack is
# never touched, so authentication cannot break if this fails midway.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write /etc/pam.d" >&2; exit 90; }
[[ -d "/etc/pam.d" ]] || { echo "/etc/pam.d not present on this host" >&2; exit 90; }

target="/etc/pam.d/ks-noise-probe"
cleanup() { rm -f "$target"; }
trap cleanup EXIT
rm -f "$target"

printf '%s\n' '# kernelsentinel scenario, not a real policy' > "$target"
chmod "644" "$target"

echo "[scenario] persistence_pam: wrote $target"
