# Compatibility

What runs where, and what silently does not. Derived from the BPF helpers and
program types each sensor actually uses, not from a guess at a floor.

## The short version

| | |
|---|---|
| **Minimum kernel** | **5.11** — nothing loads below it |
| **Full sensor set** | 5.11 with `CONFIG_BPF_LSM=y` **and** `bpf` in `/sys/kernel/security/lsm` — both, not either. Compiled-in but inactive gets you five of eleven |
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

**An attach is not a working sensor.** The kernel accepts an `lsm/` program
whether or not `bpf` is in the active LSM list; only the hook being *invoked*
depends on that. Measured on an Ubuntu runner with `bpf` absent from the list:
all eleven programs attached, and a real `chmod u+s` and a real read of
`/etc/shadow` produced nothing at all.

So the agent no longer counts them. It reads `/sys/kernel/security/lsm` at
startup and, when `bpf` is missing, reports the six `lsm/` sensors as
unavailable with that as the reason — `5 of 11 sensors active`, not `11 of 11`,
as measured when there were eleven.
Nothing is lost that the host ever had; what changes is that the operator is no
longer told the file, credential-theft, fileless-exec and container-socket
detections are watching when they are not.

`scripts/compat-probe.sh` provokes each sensor family and records which ones
answered in the `live=` field of [compat-results.txt](compat-results.txt). That
is the claim the table below rests on.

| Sensor | Needs | Kernel | Lost without BPF-LSM |
|---|---|---|---|
| exec | tracepoint, ring buffer, `bpf_get_current_task_btf` | 5.11 | — |
| fork / exit | raw tracepoint | 5.11 | — |
| commit_creds | `fentry` + BTF | 5.11 | — |
| module load | `fexit` + BTF | 5.11 | — |
| file_open | `lsm/` + `bpf_d_path` | 5.11 + BPF-LSM | ✗ |
| path_chmod | `lsm/` + `CONFIG_SECURITY_PATH` | 5.11 + BPF-LSM | ✗ |
| path_mknod | `lsm/` + `CONFIG_SECURITY_PATH` | 5.11 + BPF-LSM | ✗ |
| inode_setxattr | `lsm/` | 5.11 + BPF-LSM | ✗ |
| ptrace_access_check | `lsm/` | 5.11 + BPF-LSM | ✗ |
| bprm_check_security | `lsm/` | 5.11 + BPF-LSM | ✗ |
| unix_stream_connect | `lsm/` | 5.11 + BPF-LSM | ✗ |

Without BPF-LSM you keep process lineage, every credential transition, and
kernel module loading. You lose the file, credential-theft, fileless-exec and
container-socket detections — which is most of the detection surface, but a long
way from nothing.

## Distributions

`CONFIG_BPF_LSM=y` is the deciding factor, and it is not universal. Even where
compiled in, it must also be listed in `/sys/kernel/security/lsm`, which usually
means adding `lsm=...,bpf` to the kernel command line.

A row may say **verified** only when `scripts/compat-probe.sh` has actually
loaded the sensors there and its output is recorded in
[compat-results.txt](compat-results.txt). Each verified row carries the
distribution id the probe reported and the sensor count it observed, and a test
fails if either disagrees with the recorded evidence — so "verified" cannot be
typed next to a guess, and a count cannot drift away from what was measured.

Every other row is inferred from that distribution's shipped kernel version and
default config, and a default can change between releases. Treat them as "where
to start", and let `doctor` settle it.

| Distribution | Kernel | BPF-LSM | |
|---|---|---|---|
| **Kali rolling** | 7.0 | ✅ active by default | measured at 11/11 before `lsm/path_mknod` was added; **awaiting re-measurement** against the current 12 |
| Debian 12 (bookworm) | 6.1 | compiled in | expect to need `lsm=` on the cmdline |
| Debian 11 (bullseye) | 5.10 | — | **below the 5.11 floor**, nothing loads |
| **Ubuntu 24.04 LTS** | 6.17 (azure) | compiled in, **not active** | measured at 5/11 before `lsm/path_mknod` was added; **awaiting re-measurement** against the current 12. The `lsm/` sensors attach and stay inert until `bpf` is added to `lsm=` |
| Ubuntu 22.04 LTS | 5.15 | compiled in | expect to need `lsm=` on the cmdline |
| Fedora 38+ | 6.2+ | compiled in | |
| Arch | current | compiled in | rolling, well above the floor |
| Manjaro | current | compiled in | Arch-derived; kernel lags Arch slightly |
| CachyOS | current | compiled in | Arch-derived, custom-tuned kernels — check `doctor`, since a non-stock config is exactly where a default may differ |
| EndeavourOS / Garuda | current | compiled in | Arch kernels, unmodified |
| RHEL / Rocky / Alma 9 | 5.14 | ❌ not compiled in | core sensors only, agent still starts |
| RHEL / Rocky / Alma 8 | 4.18 | ❌ | **far below the floor** |
| Amazon Linux 2023 | 6.1 | varies | check `doctor` |

Arch and its derivatives are the easy case: rolling kernels sit far above the
5.11 floor, and `CONFIG_BPF_LSM=y` has been standard in the Arch kernel for
years. CachyOS is the one worth actually checking rather than assuming — it
ships custom-tuned kernels, and a non-stock config is precisely where a default
like `CONFIG_LSM` might diverge.

### What is still untested anywhere but one machine

CI attaches the sensors on a GitHub runner, whose kernel has BPF-LSM compiled in
but not active — and a hosted runner cannot be rebooted with a different command
line. So the six `lsm/` sensors, which carry most of the detection surface, have
never fired anywhere except the developer machine in the table below. They are
covered by replay tests against recorded captures, and by the attack suite when
someone runs it locally, but no automated run has seen one of them observe a real
event on a kernel other than that one.

That gap is now closed by `tests/vm/run.sh`, which CI runs on every push. It
boots the runner's own kernel image under QEMU with `lsm=...,bpf` appended --
the kernel already has `CONFIG_BPF_LSM=y`, only the boot parameter was missing
-- and provokes each sensor family inside the guest. Everything lives in an
initramfs, so there is no virtiofs, 9p or disk image to vary between kernels.
The job fails if only `exec` answers, because a guest that came up without the
bpf LSM has tested nothing the ordinary runner does not already cover.

Locally, on the developer machine and without KVM, the whole boot takes about
twelve seconds:

```bash
tests/vm/run.sh                     # or: tests/vm/run.sh /path/to/vmlinuz
```

### Producing a row

`scripts/compat-probe.sh` loads the sensors on whatever kernel it is run on and
prints one line describing the result:

```bash
sudo ./scripts/compat-probe.sh
```

```
ks-compat: distro=debian-12 kernel=6.1.0-21-amd64 arch=x86_64 bpflsm=active sensors=12/12 missing=none live=exec,path_chmod,file_open
```

That line is what turns an inferred row into a verified one, and it is the most
useful thing a
[compatibility report](https://github.com/SysFr4m3r/kernelsentinel/issues/new?template=compatibility.yml)
can carry. CI runs the same probe on the GitHub runner's kernel, which is a
different kernel and LSM configuration from any developer machine.

The probe deliberately does **not** require all eleven sensors. Losing the six
`lsm/` ones is supported behaviour, and a check demanding the full set would fail
every correctly-degrading kernel while passing only on machines that already
work. It asserts the object loads and that `exec` attaches; the rest is recorded,
not demanded.

Verify rather than trust a table — `doctor` answers all of it in one line each,
on any distribution, without needing a row here:

```bash
sudo kernelsentinel doctor
```

```
kernel      [ ok ] 6.1.0-21-amd64 (5.11+, all BPF features present)
btf         [ ok ] /sys/kernel/btf/vmlinux present (CO-RE enabled)
privileges  [ ok ] running as root
bpf lsm     [ ok ] bpf LSM active (lockdown,capability,landlock,yama,apparmor,bpf,...)
memlock     [ ok ] RLIMIT_MEMLOCK 8192 KiB
```

If `bpf lsm` fails, the agent still runs — it just loses the six `lsm/` sensors
and says which ones.

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

x86_64 and aarch64 are both **built, tested and attached in CI** — the aarch64
job compiles the BPF object, runs the full test suite, and loads the sensors on
an arm64 kernel. Until recently this row was an assertion about what `build.rs`
*refuses*, which is not the same as evidence that the supported targets work.
`build.rs` still rejects anything else at compile time rather than producing an
object for the wrong target. Release binaries are
published for x86_64 only — build from source for aarch64.
