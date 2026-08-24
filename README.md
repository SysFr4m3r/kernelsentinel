# KernelSentinel

[![CI](https://github.com/SysFr4m3r/kernelsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/SysFr4m3r/kernelsentinel/actions/workflows/ci.yml)

**Runtime detection engine for Linux post-exploitation and privilege-escalation behavior, using eBPF.**

Most process monitors hand you a firehose of syscalls and leave the thinking to you. KernelSentinel is
built the other way round: eBPF sensors feed a **live process behavior graph**, and a correlation
engine turns causally-linked events into a small number of high-signal, MITRE-mapped alerts.

The difference is the unit of output. Not this:

```
execve("/bin/sh")
memfd_create("", 1)
execve("/proc/self/fd/7")
setresuid(0, 0, 0)
```

But this — real output, from a real captured attack:

```
CRITICAL  risk 100/100  [T1068, T1548.001]
  zsh(4510) -> sudo(7429) -> sudo(7449) -> sh(7450) -> chmod(7452)
    privilege_escalation   changed euid 1000 -> 0; gained CAP_SYS_ADMIN,CAP_BPF,...  (+40)
    suid_create            created a new SUID binary /tmp/.x                         (+45)
  score: base 85 + chain 22 = 100
```

A web server spawning a shell that runs from memory scores itself, and shows its work:

```
CRITICAL  risk 100/100  [T1059.004, T1620]
  nginx(800) -> sh(900)
    shell_from_network_daemon   nginx(800) spawned a shell (sh)     (+50)
    fileless_exec               executed from memfd (memfd:payload)  (+45)
  score: base 95 + chain 25 x1.30 (lineage rooted at a network daemon) = 100
```

Every number decomposes into named parts, because a score nobody can explain is one nobody acts on.

---

## Project status: working detection engine (M3), developed in public

The full pipeline is built and validated on real kernel captures: **eBPF sensors → process graph →
correlation engine → scored, MITRE-mapped alerts**, in both human and NDJSON form. M0–M3 are done;
see the [Roadmap](#roadmap) for what is verified and what remains.

Still a young project — not yet a packaged release, and the false-positive tuning that separates a
production EDR from a research tool (baselining, M7) is ahead. Do not deploy it as your only line of
defense. But it detects real post-exploitation chains today, and every detection is covered by a
test replaying a real capture.

---

## What works today

**Sensors** (eBPF CO-RE, all six verified live on kernel 6.19):
- `exec` with full `argv`, `fork`/`exit`, and every credential transition via `fentry/commit_creds`
- New SUID/SGID binaries (`lsm/path_chmod`), file capabilities via setcap (`lsm/inode_setxattr`)
- Writes to watched paths — `ld.so.preload`, `authorized_keys`, cron, systemd, sudoers, shadow —
  filtered in-kernel by an LPM trie so the daemon never sees the firehose (`lsm/file_open` + `bpf_d_path`)
- `ptrace` and cross-uid `/proc` memory reads (`lsm/ptrace_access_check`)
- Docker/containerd control-socket connections (`lsm/socket_connect`) — the container-escape primitive
- Fileless execution from memfd / anonymous files (`lsm/bprm_check_security`)
- Kernel module load (`fexit/do_init_module`) — verified with a standard module

**Process graph**: PID-reuse-proof identity `(pid, start_boottime)`, parent/child edges, credential
history, ancestry walks, retention window, hard memory caps, and `/proc` bootstrap for processes that
predate the daemon.

**Detection engine**: eight built-in detections mapping events to scored signals; a correlation
engine that combines the signals in one process lineage into a single incident; explainable risk
scoring (base + chain bonus + context multiplier, with severity bands); deduplication so a chain
alerts once, not per event; and MITRE ATT&CK mapping.

**Tooling**:
- `kernelsentinel run` — the daemon (human alerts, or `--json` for NDJSON)
- `kernelsentinel investigate <pid> --capture <file>` — one process\'s full story: lineage, timeline,
  credential history, signals, risk, ATT&CK
- `kernelsentinel record` / `replay` — capture events to NDJSON, replay through the engine
  unprivileged and deterministically (this is how detections are developed and regression-tested)
- `kernelsentinel baseline` — learn per-host normal from a clean capture; `run`/`replay --baseline`
  then downweights routine behavior (a plain `sudo` stops alerting) while novel behavior is untouched
- `kernelsentinel rules` — validate YAML detection rules; `run`/`replay --rules DIR` loads custom
  match/sequence rules that flow through the same engine (see [docs/WRITING_RULES.md](docs/WRITING_RULES.md))
- **Fleet monitoring**: `kernelsentinel serve` runs a central web panel; agents `ship` their incidents
  to it and admins log in to a read-only dashboard that ranks hosts by score. Data flows one way
  (host → central), so the dashboard can audit activity but never reach into a host. Supports
  per-agent keys (a leaked key can't impersonate other hosts), a persistence journal (reports
  survive restarts), and TLS with client-side certificate pinning
- `kernelsentinel tree`, `doctor`

**Tested**: 26 tests, including detections replayed from **real kernel captures** committed as
fixtures — the strongest possible regression net. The false-positive discipline (a bare `sudo` must
not alert; `sshd` spawning a shell is a login, not an intrusion) is enforced by tests.

## Requirements

| | |
|---|---|
| Kernel | **5.8+** (ring buffer). BPF-LSM sensors from M2 want **5.7+** with `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm` |
| BTF | `/sys/kernel/btf/vmlinux` must exist (`CONFIG_DEBUG_INFO_BTF=y`) |
| Privileges | root, or `CAP_BPF` + `CAP_PERFMON` |
| Toolchain | clang 11+, libbpf 1.x, bpftool, Rust 1.75+ |

Developed against kernel 6.19 on Kali. `kernelsentinel doctor` will tell you where your host stands.

## Install

**1. Toolchain.** The BPF side is compiled with clang against libbpf; the userspace is Rust.

```bash
sudo apt install -y clang llvm libelf-dev zlib1g-dev libbpf-dev bpftool pkg-config
```

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
```

**2. Generate `vmlinux.h`.** It is host-specific and not committed; CO-RE regenerates it from
your kernel's BTF (this is also exactly what CI does):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

**3. Build.**

```bash
cargo build --release
```

The binary is `target/release/kernelsentinel`. Everything below assumes it is on your `PATH`
(or run it by that path).

**Check your host is supported** — this reports kernel, BTF, LSM, and privileges, and exits
non-zero if a hard requirement is missing:

```bash
sudo kernelsentinel doctor
```

## Run — single host

```bash
sudo kernelsentinel run
```

The daemon — it streams events and raises correlated incidents:

```bash
sudo ./target/release/kernelsentinel run
```

Emit incidents as NDJSON for a SIEM or pipeline (suppresses the event stream):

```bash
sudo kernelsentinel run --json
```

Each incident is one self-contained, version-tagged JSON object:

```json
{"schema":"kernelsentinel.incident/v1","severity":"CRITICAL","score":100,
 "subject":{"pid":7452,"comm":"chmod","exe":"/usr/bin/chmod","uid":0},
 "lineage":["zsh(4510)","sudo(7429)","sh(7450)","chmod(7452)"],
 "attack":["T1068","T1548.001"],"signals":[…]}
```

### Try it without waiting for an attack

`record` captures events; `replay` runs them back through the engine unprivileged and
deterministically — no root, no kernel:

```bash
sudo kernelsentinel record -o capture.ndjson
```

```bash
kernelsentinel replay capture.ndjson
```

The repository ships real captures as fixtures, so you can see a detection immediately:

```bash
kernelsentinel replay tests/fixtures/host_sudo_suid.ndjson
```

### Investigate one process

```bash
kernelsentinel investigate 7452 --capture tests/fixtures/host_sudo_suid.ndjson
```

```
=== PID 7452 chmod ===
executable : /usr/bin/chmod
lineage    : zsh(4510) -> sudo(7429) -> sudo(7449) -> sh(7450) -> chmod(7452)
risk       : CRITICAL 100/100  (base 85 + chain 22)
signals:
  privilege_escalation   changed euid 1000 -> 0; gained CAP_SYS_ADMIN,...  (+40)
  suid_create            created a new SUID binary /tmp/.x                 (+45)
MITRE ATT&CK:
  T1068        Exploitation for Privilege Escalation
  T1548.001    Setuid and Setgid
```

## Run — fleet (central web panel)

One binary, two roles chosen by subcommand: on monitored hosts it's the **agent**
(`run` + `ship`); on the central box it's the **server** (`serve`). Telemetry flows
one way — host → central — so the dashboard can audit activity but never reach into
a host. (See [The binary](#the-binary) for why it's one binary.)

### On the central server

Generate a TLS cert (or use one from your CA), and a per-host key for each agent.
Then start the server:

```bash
export KS_ADMIN_PASSWORD='choose-a-strong-admin-password'

kernelsentinel serve \
  --bind 0.0.0.0:8088 \
  --keys /etc/kernelsentinel/agents.keys \
  --journal /var/lib/kernelsentinel/incidents.sqlite \
  --retain-days 90 \
  --tls-cert /etc/kernelsentinel/server.pem \
  --tls-key  /etc/kernelsentinel/server.key
```

`agents.keys` is one `hostname key` per line — the key **binds** the host, so a
leaked key can only ever write its own host's data:

```text
web-prod-01   4f8c1e…   # generate each with: openssl rand -hex 32
db-app-03     9a2b7d…
```

Admins then open `https://central:8088`, sign in with the admin password, and get
the host list ranked by score.

### On each monitored VM

Copy the binary and the server's certificate to the VM. Then pipe live incidents
to the server — this is the agent:

```bash
export KS_INGEST_KEY='this-vms-key-from-agents.keys'

sudo kernelsentinel run --json \
  | kernelsentinel ship https://central:8088/api/ingest \
      --host web-prod-01 \
      --ca /etc/kernelsentinel/server.pem
```

- `run --json` is the root collector emitting incidents as NDJSON.
- `ship` forwards them to the server; `--ca` **pins** the server's certificate
  (the agent trusts only that exact cert — no public CA can impersonate the server).
- `--host` labels this VM (or omit it to use the system hostname).

Run it under systemd so it stays up. A minimal unit:

```ini
[Service]
Environment=KS_INGEST_KEY=this-vms-key
ExecStart=/bin/sh -c '/usr/local/bin/kernelsentinel run --json | /usr/local/bin/kernelsentinel ship https://central:8088/api/ingest --ca /etc/kernelsentinel/server.pem'
Restart=always
```

> **No TLS yet?** For a quick localhost trial, drop the `--tls-*` and `--ca` flags
> and use `http://`. The server then binds `127.0.0.1` and warns; never expose
> plain HTTP off localhost — the ingest key travels in a header.

### The binary

It's **one binary** today. The same `kernelsentinel` is the agent (`run`/`ship`)
on hosts and the server (`serve`) on the central box — you deploy the same file
everywhere and pick the role with the subcommand. This keeps the build and
distribution simple.

The one caveat: the central server carries the eBPF collector code it never runs,
and building from source needs the BPF toolchain. For a production central box
that shouldn't have that toolchain, a **server-only build** (no eBPF) is the clean
split — planned, not yet done. Until then, build once on a machine with the
toolchain and copy the binary to the server.

## Custom detection rules## Custom detection rules

Add detections in YAML without recompiling — see [docs/WRITING_RULES.md](docs/WRITING_RULES.md):

```bash
kernelsentinel rules --dir rules            # validate + list
sudo kernelsentinel run --rules rules       # load alongside the built-ins
```

## Suppress routine behavior (baselining)

Learn a host's normal from a clean capture, then apply it so routine actions (a plain `sudo`)
stop alerting while novel behavior still fires:

```bash
kernelsentinel baseline --capture clean.ndjson --out host.baseline
sudo kernelsentinel run --baseline host.baseline
```

## Architecture

```
┌──────────────────────────────────────────────┐
│                 eBPF sensors                 │
│                                              │
│  exec   fork/exit   commit_creds   ptrace    │
│  file_open   inode_setattr   setxattr        │
│  memfd   module_load   setns   socket        │
└───────────────────┬──────────────────────────┘
                    │ ring buffer (8MB, drop-counted)
                    ▼
┌──────────────────────────────────────────────┐
│              userspace agent (Rust)          │
│                                              │
│   process graph  ·  event correlation        │
│   credential history  ·  namespace tracking  │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│              detection engine                │
│                                              │
│   built-in detections  ·  YAML rule DSL      │
│   sequence matching    ·  risk scoring       │
└───────────────────┬──────────────────────────┘
                    │
                    ▼
              CLI  ·  NDJSON
```

## Design notes

A few decisions that shape everything else, and why the obvious alternative is wrong:

**Hook LSM and `commit_creds`, not syscalls.** `sys_enter_setuid` misses credential transitions that
don't come through that syscall — SUID exec, `capset`, kernel paths — and double-fires on others.
Hooking `commit_creds` and diffing old against new credentials catches *every* transition, for free.

**Never read a path from a userspace pointer at syscall entry.** It is pre-canonicalization and
TOCTOU-racy, which is a real detection bypass rather than a theoretical one. File sensors use LSM
hooks with `bpf_d_path()` on the resolved `struct file`. Even `argv` is read from the new process's
`mm->arg_start` *after* the exec completes.

**Process identity is `(pid, start_boottime)`, never a bare PID.** PIDs recycle within seconds on a
busy host, and a recycled PID means attributing an attacker's action to an innocent process.

**Filter in the kernel.** Path-based sensors consult an LPM trie of watched prefixes inside the BPF
program. Shipping every `file_open` to userspace would melt the host.

**Detect memfd execution structurally.** String-matching `/proc/self/fd/` is trivially evaded by
re-opening the descriptor elsewhere; the superblock magic and `memfd:` dentry name are not.

**Risk scores are explainable.** Fixed per-signal contributions, a chain multiplier so causally-linked
signals beat unrelated ones, context modifiers, and exponential decay. Every alert prints its
breakdown, because a score nobody can explain is a score nobody acts on.

## Why a graph, and not more rules

A 40-second capture on an idle desktop produced 230 exec events, 79% of them from a single panel
applet polling for a VPN address once a second. In the same capture, an automated shell session
appeared as: a non-interactive `zsh -c` spawned by a non-shell parent, sourcing a script from a
dotfile directory, immediately spawning a binary that recursively scanned the filesystem.

Structurally, that is indistinguishable from a webshell dropping into reconnaissance. What separates
them is not in any single event — it is the ancestry (the parent is a terminal in a user session, not
a network daemon), the credential history (no uid transition), and the session context.

Per-event rules cannot see any of that, which is why the process graph is M1 and additional sensors
are M2. Sensors without correlation produce a tool that cries wolf, and a tool that cries wolf gets
turned off.

A second measurement makes the same point from the other direction. A single `sudo id` produces
**eight** credential transitions — sudo brackets its privileges, dropping to euid 1 and back around
each operation. Every one is a real transition, correctly captured, and individually meaningless.
The fact worth alerting on is the net result (`uid 1000 → 0, gained CAP_SYS_ADMIN`), which only
exists once you correlate them per process.

## Roadmap

| | Milestone | Status |
|---|---|---|
| M0 | BPF pipeline, exec sensor, `doctor` | ✅ done & verified |
| M1 | fork/exit, `commit_creds`, process graph, `/proc` bootstrap | ✅ done & verified |
| M2 | File sensors (LSM, `bpf_d_path`), ptrace, memfd, module load | ✅ done & verified (all 6 sensors) |
| M3 | Built-in detections, risk scoring, alerts, `investigate`, NDJSON — **first usable release** | ✅ done & validated |
| M4 | `record`/`replay`, Docker lab, real-capture fixtures | ✅ core done |
| M5 | YAML rule DSL (match + sequence rules) | ✅ first increment |
| M6 | Container & namespace awareness | 🚧 container id + context + escape detection |
| M7 | Baselining ✅ first increment · YARA, optional enforcement · (NDJSON/SIEM done in M3) | 🚧 in progress |

## Planned detections

Process credential changes · new SUID/SGID binaries · file capability changes via `setcap` ·
`/etc/ld.so.preload` writes · `authorized_keys` modification · cron and systemd unit changes ·
kernel module loading · `ptrace` into another process · `/proc/<pid>/{mem,environ,maps}` access ·
shells spawned from network-facing daemons · execution from `/tmp`, `/dev/shm`, and memfd ·
namespace manipulation · Docker socket access · container escape shapes.

Each is documented in **[docs/DETECTIONS.md](docs/DETECTIONS.md)** with its ATT&CK technique, score, how to trigger it, and its known false positives **and known evasions**.

## Limitations

Stated up front, because a security tool that hides these is worse than one that has them:

- **Detect-only.** No prevention. Enforcement via BPF-LSM return codes is a stretch goal, not a promise.
- **Not an auditd replacement.** KernelSentinel logs what feeds detections, not everything.
- **eBPF sees nothing before it attaches.** The `/proc` bootstrap reconstructs existing processes, but
  their history is inferred and marked as such.
- **Paths are best-effort.** Mount namespaces, bind mounts, and overlayfs all complicate resolution;
  events carry `(dev, inode)` alongside the path so it can be re-resolved.
- **A determined attacker with root can unload the sensors.** This is a detection tool, not a rootkit
  defense.
- **False positives are the hard part.** Package managers, `sudo`, systemd, container runtimes, and CI
  all do "suspicious" things constantly. Tuning that out is the ongoing work, tracked by a nightly
  job that asserts zero alerts under real workloads.

## Testing

⚠️ The attack scenarios in `tests/scenarios/` are **deliberately destructive** — they create SUID
binaries, load modules, and write to `/etc`. Run them only in a disposable VM, never on your host.

```bash
cargo test
```

## License

Dual-licensed, split by directory:

- **`bpf/` — GPL-2.0** ([`bpf/LICENSE`](bpf/LICENSE)). Not a formality: `bpf_d_path()` and
  `bpf_probe_read_kernel_str()` are GPL-only helpers, and the verifier rejects a program whose
  `license` section does not declare a GPL-compatible license.
- **Everything else — Apache-2.0 OR MIT**, at your option
  ([`LICENSE-APACHE`](LICENSE-APACHE), [`LICENSE-MIT`](LICENSE-MIT)) — the Rust ecosystem convention.

Unless you state otherwise, contributions are accepted under these same terms.

## Documentation

- **[docs/DETECTIONS.md](docs/DETECTIONS.md)** — every detection: what it catches, its ATT&CK
  technique and score, how to trigger it, and its known false positives and evasions.
- **[docs/WRITING_RULES.md](docs/WRITING_RULES.md)** — add detections in YAML, no recompile: the
  match/sequence rule DSL, conditions, and scoping.

## Reading

- [BPF CO-RE reference guide](https://nakryiko.com/posts/bpf-core-reference-guide/) — Andrii Nakryiko
- [libbpf-rs](https://github.com/libbpf/libbpf-rs) — the Rust bindings this is built on
- [MITRE ATT&CK for Linux](https://attack.mitre.org/matrices/enterprise/linux/)
