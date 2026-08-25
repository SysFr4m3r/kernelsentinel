# Changelog

Notable changes per release. Dates are release dates; the detail behind each
line is in the commit history.

## v0.1.0 — first packaged release

The full pipeline, validated on real kernel captures: **eBPF sensors → process
graph → correlation → scored, MITRE-mapped incidents**, plus a central fleet
panel.

### Detection
- Nine eBPF CO-RE sensors: exec/fork/exit, every credential transition via
  `commit_creds`, new SUID/SGID binaries, file capabilities, writes to watched
  paths, ptrace and cross-uid `/proc` reads, Docker/containerd socket access,
  fileless execution, kernel module load.
- Credential-store and SSH private key **reads** — the theft shape, distinct
  from the tampering a write means.
- Process graph with PID-reuse-proof identity `(pid, start_boottime)`,
  credential history, and `/proc` bootstrap.
- Explainable scoring: base + chain bonus + context multiplier, with the
  breakdown printed on every alert.
- YAML rule DSL, per-host baselining, and YARA content scanning triggered by
  behaviour rather than run over every file.

### Fleet
- `serve` runs a read-only web panel; agents `ship` incidents to it. Telemetry
  is one-way — no channel from the panel back to a host.
- Per-agent keys bind a host, TLS with client-side certificate pinning, sqlite
  journal with an audit trail, and user accounts with argon2 hashing.
- Real-time updates by long-poll, fleet-wide activity view with search, and
  per-signal timestamps and command lines.
- Agent heartbeat, so a dead agent is distinguishable from a healthy host, and
  ring-buffer drop telemetry, so lost events are never presented as coverage.
- Alert delivery to a webhook or syslog, rate limited and off the ingest path.

### Safety and hardening
- Secrets on command lines are redacted before argv leaves the host.
- Failed logins are rate limited per source address.
- Schema versioning with a refusal to open a database written by a newer build.
- WAL journaling, an absolute row ceiling, and periodic pruning.

### Packaging
- `kernelsentinel-agent` and `kernelsentinel-server` Debian packages, plus
  tarballs and checksums.
- The server builds with `--no-default-features` and needs **no BPF toolchain**:
  no clang, no libbpf, no `vmlinux.h`.

### Known limitations
Detect-only, no prevention. The false-positive rate has not yet been measured
over a sustained period on a busy host — the tuning that separates this from a
production EDR is still ahead. See the README's Limitations section, and
`docs/DETECTIONS.md` for the known false positives and evasions of every
detection.
