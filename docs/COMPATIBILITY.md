# Compatibility

What runs where, and what silently does not. Derived from the BPF helpers and
program types each sensor actually uses, not from a guess at a floor.

## The short version

| | |
|---|---|
| **Minimum kernel** | **5.11** — nothing loads below it |
| **Full sensor set** | 5.11 with `CONFIG_BPF_LSM=y` **and** `bpf` in `/sys/kernel/security/lsm` |
| **Architectures** | x86_64, aarch64 |
| **Release binaries** | glibc 2.35+ (built on Ubuntu 22.04) |
| **Privileges** | root, or `CAP_BPF` + `CAP_PERFMON` |

5.11 rather than the 5.8 this project claimed until recently: every program calls
`fill_hdr`, which uses `bpf_get_current_task_btf()`, added in 5.11. A 5.8–5.10
kernel has the ring buffer but not that helper, so the object fails to load
outright rather than degrading.

## Per-sensor requirements

The agent attaches each program separately and reports which ones did not, so a
kernel missing BPF-LSM loses the file, ptrace, exec-source and socket sensors
while keeping the rest — it does not refuse to start.

| Sensor | Needs | Kernel | Lost without BPF-LSM |
|---|---|---|---|
| exec | tracepoint, ring buffer, `bpf_get_current_task_btf` | 5.11 | — |
| fork / exit | raw tracepoint | 5.11 | — |
| commit_creds | `fentry` + BTF | 5.11 | — |
| module load | `fexit` + BTF | 5.11 | — |
| file_open | `lsm/` + `bpf_d_path` | 5.11 + BPF-LSM | ✗ |
| path_chmod | `lsm/` + `CONFIG_SECURITY_PATH` | 5.11 + BPF-LSM | ✗ |
| inode_setxattr | `lsm/` | 5.11 + BPF-LSM | ✗ |
| ptrace_access_check | `lsm/` | 5.11 + BPF-LSM | ✗ |
| bprm_check_security | `lsm/` | 5.11 + BPF-LSM | ✗ |
| socket_connect | `lsm/` | 5.11 + BPF-LSM | ✗ |

Without BPF-LSM you keep process lineage, every credential transition, and
kernel module loading. You lose the file, credential-theft, fileless-exec and
container-socket detections — which is most of the detection surface, but a long
way from nothing.

## Distributions

`CONFIG_BPF_LSM=y` is the deciding factor, and it is not universal. Even where
compiled in, it must also be listed in `/sys/kernel/security/lsm`, which usually
means adding `lsm=...,bpf` to the kernel command line.

| Distribution | Kernel | BPF-LSM | Notes |
|---|---|---|---|
| Ubuntu 22.04 LTS | 5.15 | ✅ compiled in | usually needs `lsm=` on the cmdline |
| Ubuntu 24.04 LTS | 6.8 | ✅ | |
| Debian 12 (bookworm) | 6.1 | ✅ compiled in | needs `lsm=` on the cmdline |
| Debian 11 (bullseye) | 5.10 | — | **below the 5.11 floor** |
| Fedora 38+ | 6.2+ | ✅ | |
| RHEL / Rocky / Alma 9 | 5.14 | ❌ not compiled in | core sensors only |
| RHEL / Rocky / Alma 8 | 4.18 | ❌ | **far below the floor** |
| Amazon Linux 2023 | 6.1 | varies | check `doctor` |
| Kali / Arch | current | ✅ | developed here |

Verify rather than trust a table:

```bash
sudo kernelsentinel doctor
```

## Enabling BPF-LSM

If `doctor` reports BPF-LSM compiled in but not active, add it to the boot
command line and reboot:

```
lsm=lockdown,capability,landlock,yama,apparmor,bpf
```

Keep the distribution's existing list and append `bpf` — dropping an entry
disables that security module.

## Containers

The agent runs on the **host**, not in a container: it needs `CAP_BPF` and the
host's own kernel view. Host sensors observe containers because they share a
kernel, which is how the container detections work at all.

The fleet server has no kernel requirement of any kind. Build it with
`--no-default-features` and it runs anywhere glibc does.

## Architectures

x86_64 and aarch64 are supported; `build.rs` rejects anything else at compile
time rather than producing an object for the wrong target. Release binaries are
published for x86_64 only — build from source for aarch64.
