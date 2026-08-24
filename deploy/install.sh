#!/usr/bin/env bash
# Deploy KernelSentinel on this host: install the binary, provision config +
# TLS + a per-agent key, and start the server and agent as systemd services.
# Run with sudo from the repo root:  sudo ./deploy/install.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$REPO/target/release/kernelsentinel}"
HOST="$(hostname)"
ETC=/etc/kernelsentinel
DATA=/var/lib/kernelsentinel

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
[[ -x "$BIN" ]] || { echo "binary not found at $BIN -- run: cargo build --release"; exit 1; }

echo "==> installing binary"
install -m755 "$BIN" /usr/local/bin/kernelsentinel

echo "==> creating server user + directories"
id kernelsentinel &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin kernelsentinel
mkdir -p "$ETC" "$DATA"

if [[ ! -f "$ETC/server.pem" ]]; then
  echo "==> generating self-signed TLS cert (CN=$HOST)"
  openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout "$ETC/server.key" -out "$ETC/server.pem" \
    -subj "/CN=$HOST" -addext "subjectAltName=DNS:localhost,DNS:$HOST" 2>/dev/null
fi

if [[ ! -f "$ETC/agents.keys" ]]; then
  KEY="$(openssl rand -hex 32)"
  echo "$HOST  $KEY" > "$ETC/agents.keys"
  echo "KS_INGEST_KEY=$KEY" > "$ETC/agent.env"
  echo "==> generated agent key for host '$HOST'"
fi

if [[ ! -f "$ETC/server.env" ]]; then
  PW="$(openssl rand -hex 12)"
  echo "KS_ADMIN_PASSWORD=$PW" > "$ETC/server.env"
  echo "==> generated admin password: $PW   (also in $ETC/server.env)"
fi

echo "==> permissions"
chmod 644 "$ETC/server.pem"                 # public cert, agent reads it
chmod 640 "$ETC/server.key" "$ETC/agents.keys" "$ETC/server.env"
chmod 600 "$ETC/agent.env"                  # root-only (agent runs as root)
chown root:kernelsentinel "$ETC/server.key" "$ETC/agents.keys" "$ETC/server.env"
chown -R kernelsentinel:kernelsentinel "$DATA"

echo "==> installing + starting systemd services"
install -m644 "$REPO/deploy/kernelsentinel-server.service" /etc/systemd/system/
install -m644 "$REPO/deploy/kernelsentinel-agent.service"  /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now kernelsentinel-server
systemctl enable --now kernelsentinel-agent

echo
echo "Done. Dashboard:  https://$HOST:8088   (or https://localhost:8088)"
echo "Admin password:   $(grep -o 'KS_ADMIN_PASSWORD=.*' "$ETC/server.env" | cut -d= -f2)"
echo "Status:           systemctl status kernelsentinel-server kernelsentinel-agent"
echo "Logs:             journalctl -u kernelsentinel-server -u kernelsentinel-agent -f"
