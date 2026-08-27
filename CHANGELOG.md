# Changelog

Notable changes per release. Dates are release dates; the detail behind each
line is in the commit history.

## v0.2.0 — container escape detection and optional enforcement

### Detection
- **Kernel escape hatches**: writes to `core_pattern`, `modprobe`, `poweroff_cmd`,
  `uevent_helper` and `binfmt_misc/register`. Each names a program the kernel runs
  as root on the host, so the same write is persistence from a host and an
  *escape* from inside a container — and scores accordingly (45 vs 75).
- **Namespace escape**: a process whose cgroup says container while its mount
  namespace says host. Scoped to the mount namespace deliberately; `--net=host`
  and `--pid=host` are ordinary configuration and flagging them would bury the
  signal in normal Kubernetes.
- Namespaces are read at `exec` only, and the host's own namespace is read once
  at startup and carried on the graph — so detection stays deterministic under
  replay instead of depending on the machine doing the replaying.

### Enforcement (new, off by default)
- `--enforce off|audit|on`. Blocks exactly one case: escape-hatch writes from a
  non-host mount namespace. `audit` reports what would be blocked and blocks
  nothing; run it first.
- Every uncertain path fails **open** — no config, no known host namespace, an
  unreadable namespace, or a ring buffer too full to record the event. Denial
  refuses to arm at all without a known host namespace, because guessing would
  mean denying on the host itself.
- A blocked operation is still recorded and the incident leads with `BLOCKED:`.
  The score is unchanged: blocking changes the outcome, not the severity of the
  attempt.

### Verified
Both milestones were loaded on a real kernel (6.19) before release: the
namespace CO-RE reads and the enforcement map lookup passed the BPF verifier,
with zero ring-buffer drops in detect-only and audit modes.

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
