# Deploying KernelSentinel on one host (server + agent)

For a real single-box test: the **server** (central web panel) and the **agent**
(eBPF collector) both run here as systemd services.

```bash
cargo build --release
sudo ./deploy/install.sh
```

This installs the binary to `/usr/local/bin`, creates an unprivileged
`kernelsentinel` user for the server, generates a self-signed TLS cert and a
per-host ingest key under `/etc/kernelsentinel/`, and starts two services:

- `kernelsentinel-server` — the web panel, unprivileged, on `:8088` (TLS).
- `kernelsentinel-agent` — `run --json | ship` to the server, as root (eBPF
  needs CAP_BPF), pinning the server's cert.

The script prints the admin password. Open `https://localhost:8088` and sign in.

Uninstall: `sudo ./deploy/uninstall.sh`.
