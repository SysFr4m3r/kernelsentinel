#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
systemctl disable --now kernelsentinel-agent kernelsentinel-server 2>/dev/null || true
rm -f /etc/systemd/system/kernelsentinel-{server,agent}.service
systemctl daemon-reload
echo "Stopped and removed services. Config in /etc/kernelsentinel and data in"
echo "/var/lib/kernelsentinel were LEFT in place. Remove them manually if desired,"
echo "along with: userdel kernelsentinel; rm /usr/local/bin/kernelsentinel"
