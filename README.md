# KernelSentinel

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

But this:

```
CRITICAL  Suspicious privilege escalation chain            risk 94/100

  nginx (uid=33, pid=1204)
    └─ sh                          spawned shell from network daemon   +25
        ├─ memfd_create()          anonymous executable created        +45
        ├─ execve(memfd:)          executed from memory, never on disk  ×
        └─ setresuid(0,0,0)        uid 33 → 0                          +40
            └─ bash

  ATT&CK: T1059.004, T1620, T1548
```

---

## ⚠️ Project status: early (M0 of 8)

This is an in-progress build, developed in public. **Today it is an exec logger with a working
CO-RE/BPF pipeline — it does not detect anything yet.** The detection engine described above is the
design target, not the current behavior. See [Roadmap](#roadmap) for what actually works.

Do not deploy this on anything you care about.

---

## What works today

- CO-RE BPF pipeline: build → skeleton → load → attach → ring buffer → decode
- `sched_process_exec` sensor with full `argv`, resolved filename, uid/euid, cgroup id, and the
  PID-reuse-proof process key
- `kernelsentinel doctor` — preflight report on kernel, BTF, LSM, and privileges
- Ring buffer drop accounting (a silent EDR is worse than no EDR)
- Struct-layout test that fails the build if the C and Rust event definitions drift

Verified on kernel 6.19.14: ~6 exec/sec on an idle desktop, zero ring buffer drops, command lines
intact up to the 512-byte truncation boundary.

## Requirements

| | |
|---|---|
| Kernel | **5.8+** (ring buffer). BPF-LSM sensors from M2 want **5.7+** with `CONFIG_BPF_LSM=y` and `bpf` in `/sys/kernel/security/lsm` |
| BTF | `/sys/kernel/btf/vmlinux` must exist (`CONFIG_DEBUG_INFO_BTF=y`) |
| Privileges | root, or `CAP_BPF` + `CAP_PERFMON` |
| Toolchain | clang 11+, libbpf 1.x, bpftool, Rust 1.75+ |

Developed against kernel 6.19 on Kali. `kernelsentinel doctor` will tell you where your host stands.

## Build

```bash
sudo apt install -y clang llvm libelf-dev zlib1g-dev libbpf-dev bpftool pkg-config
```

`vmlinux.h` is host-specific and generated, not committed — make it first:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

```bash
cargo build --release
```

## Run

```bash
./target/release/kernelsentinel doctor
```

```bash
sudo ./target/release/kernelsentinel run
```

```
TIME         PID     PPID    UID    COMM             EVENT
14:22:03.118 18342   1204    33     sh               exec /bin/sh
14:22:03.140 18351   18342   33     id               exec /usr/bin/id
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

## Roadmap

| | Milestone | Status |
|---|---|---|
| M0 | BPF pipeline, exec sensor, `doctor` | ✅ done & verified |
| M1 | fork/exit, `commit_creds`, process graph, `/proc` bootstrap | next |
| M2 | File & credential sensors (LSM, `bpf_d_path`), ptrace, memfd, module load | |
| M3 | Built-in detections, risk scoring, alerts, `investigate` — **first usable release** | |
| M4 | `record`/`replay` + scenario test harness | |
| M5 | YAML rule DSL | |
| M6 | Container & namespace awareness | |
| M7 | Baselining, YARA, SIEM output, optional enforcement | |

## Planned detections

Process credential changes · new SUID/SGID binaries · file capability changes via `setcap` ·
`/etc/ld.so.preload` writes · `authorized_keys` modification · cron and systemd unit changes ·
kernel module loading · `ptrace` into another process · `/proc/<pid>/{mem,environ,maps}` access ·
shells spawned from network-facing daemons · execution from `/tmp`, `/dev/shm`, and memfd ·
namespace manipulation · Docker socket access · container escape shapes.

Each will be documented in `docs/DETECTIONS.md` with its known false positives **and known evasions**.

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

## Reading

- [BPF CO-RE reference guide](https://nakryiko.com/posts/bpf-core-reference-guide/) — Andrii Nakryiko
- [libbpf-rs](https://github.com/libbpf/libbpf-rs) — the Rust bindings this is built on
- [MITRE ATT&CK for Linux](https://attack.mitre.org/matrices/enterprise/linux/)
