# Detections

One entry per built-in detection: what it catches, its MITRE ATT&CK technique,
its base score, how to trigger it, and — the part that matters most — its **known
false positives** and **known evasions**. A detection tool that hides these is
worse than one that has them.

Scores are the *base* contribution of a single signal. The real severity comes
from correlation: signals in one process lineage combine, with a chain bonus for
distinct kinds and context multipliers (×1.3 rooted at a network daemon, ×1.1
inside a container). Severity bands: `<25 info · 25–49 low · 50–74 medium ·
75–89 high · ≥90 critical`. The daemon alerts at medium and above by default, so
most single signals below stay quiet until they chain — this is deliberate: single
events should not cry wolf.

Every detection here is covered by a test that replays a capture — several from
**real** kernel captures committed under `tests/fixtures/`.

## What "baseline them" means below

Several entries answer a false positive with *baseline them*. That advice is
incomplete on its own, and following it literally does not work.

A baseline entry earns suppression in proportion to the evidence behind it: how
many times the `(signal, executable)` pair was seen, and how much of the learning
window it spanned. **A pair seen once keeps about 85% of its score.** That is
deliberate — otherwise an attacker resident while you recorded a "clean" capture
would whitelist themselves with a single action — but it means recording a single
run of the noisy activity and learning from that suppresses almost nothing.

So *baseline them* means: record the host while the activity happens **the way it
normally happens** — repeatedly, across hours — and learn from that. The pair has
to look like a habit, because that is the only thing that distinguishes routine
from an intrusion that happened once.

`kernelsentinel baseline` prints what it learned and warns when nothing in the
capture is well evidenced. `budget --capture X --baseline Y` shows what the
baseline actually removed. Neither of those is optional reassurance; a baseline
that suppresses nothing is silently useless.

This is verified rather than asserted: `tests/noise/admin_config_change.sh` runs
config-management writes, learns from them, and fails if the same activity is not
quiet afterwards. **Measured:** eight alerts at the operational floor without a
baseline, zero with one learned from the same activity recurring, from two
learned patterns both rated strong.

The first version of that test learned from a *single* run and failed — which is
how this section came to be written.

---

## Process & privilege

### `privilege_escalation` — base 40 · T1068
A process's effective uid becomes 0, or it gains a dangerous capability
(`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_BPF`,
`CAP_DAC_READ_SEARCH`) it did not hold. Detected at `commit_creds`, so it catches
*every* transition — setuid/setresuid, `capset`, SUID exec, and kernel paths that
never touch a syscall — from one place.

**One signal per transition.** `commit_creds` installs a new uid and its
capabilities together; scoring them separately made an ordinary `sudo` chain to a
false critical. A bare escalation is low and suppressed on its own; it matters
only combined with another signal in the lineage.

- **Trigger:** `sudo id`
- **False positives:** every legitimate `sudo`/`su`/`pkexec` is an escalation.
  Low alone, so suppressed — and once baselined (`privilege_escalation` on
  `/usr/bin/sudo`) from a capture long enough to show it recurring, downweighted
  to near-zero even in combination. A single sighting during learning is not
  enough; see *Suppress routine behavior* in the README.
- **Evasions:** an attacker who is *already* root performs no transition, so
  there is nothing to detect here — later actions (module load, `/proc` reads)
  are the signal instead.

### `suid_create` — base 45 · T1548.001
A regular file gains the setuid or setgid bit (`0 → S_ISUID/S_ISGID`), detected at
`path_chmod` before the mode is applied, so both the old and new mode are visible.

- **Trigger:** `cp /bin/sh /tmp/.x && chmod u+s /tmp/.x`
- **False positives:** package managers (`dpkg`, `rpm`) create SUID binaries on
  install; `sudo chmod u+s` by an admin is structurally identical to the attack.
  **Measured:** a real `dpkg -i` of a package shipping a mode-4755 file does fire
  `suid_create`, attributed to `/usr/bin/dpkg` — but at 45 it is LOW, below the
  medium floor the daemon alerts at, so an ordinary package install does not page
  anyone unless it chains with something else. `tests/noise/package_install.sh`
  asserts exactly that. Baselining is only needed if you run below medium.
  If you do, learn it as normal and novel stays flagged (see *What "baseline
  them" means* above: the activity has to recur in the capture).
  **Baseline the real installer, not a shell.** The pair learned is `(suid_create,
  exe)`, so learning from `dpkg` quietens package installs while learning from a
  capture where a shell did the `chmod` suppresses `chmod u+s` from *any* shell on
  the host — the same advice, and one of the two blinds the detection it was
  meant to quieten. `tests/noise/package_install.sh` uses a real `dpkg -i` for
  exactly this reason. It
  takes a learning window long enough to show the package manager doing it more
  than once; one sighting barely suppresses, on purpose.
- **Two hooks, because one route never chmods.** `path_chmod` catches the
  transition `0 → S_ISUID`, and `path_mknod` catches a file created already-SUID.
  Both were measured rather than reasoned about: `cp -p` fires the first (it
  `fchmod`s internally, reaching the same hook, so the old note calling it an
  evasion was wrong), while `open("/tmp/.x", O_CREAT, 04755)` produced **no event
  at all** until `path_mknod` was added. Scenarios `suid_create_preserved.sh` and
  `suid_create_direct.sh` hold both routes down.
- **`path_mknod` reports the file name, not its path.** `bpf_d_path` is refused
  on that hook — the kernel allows it only on LSM hooks it treats as sleepable,
  which `path_chmod` is and `path_mknod` is not — so the event carries the leaf
  name with the degraded-path flag set.
- **Evasions:** requires `CONFIG_SECURITY_PATH` (both hooks); on kernels without
  it the `inode_setattr` fallback is still TODO. A file that is moved into place
  already SUID (`rename` from elsewhere on the same filesystem) passes through
  neither hook.

### `setcap` — base 40 · T1548
A file gains capabilities via the `security.capability` xattr — a SUID-equivalent
backdoor with no SUID bit and no visible mode change.

- **Trigger:** `setcap cap_setuid+ep /tmp/.x` (needs `CAP_SETFCAP`)
- **False positives:** package installs set file capabilities (`ping`, `dumpcap`).
  Baseline them.
- **Evasions:** the path is reported as a leaf name only (the `inode_setxattr`
  hook has a dentry, not a `struct path`, so `bpf_d_path` is unavailable);
  correlation by `(dev, inode)` is future work.

## Execution

### `fileless_exec` — base 45 · T1620
Execution of a binary that never touched disk: a `memfd`, an anonymous-inode file,
or an unlinked (deleted) file, detected at `bprm_check_security`.

- **Trigger:** `memfd_create` + write a binary + `execve("/proc/self/fd/N")`
- **Key design point:** the signal is the `memfd:` dentry name or the anonymous
  superblock, **not** the `/proc/self/fd/` path string — which is trivially
  evaded by re-opening the descriptor elsewhere.
- **False positives:** some language runtimes and packers legitimately exec from
  memory; rare enough to warrant a look.
- **Evasions:** an attacker who writes the payload to disk first is caught by
  other detections (`exec_from_tmp`, `suid_create`) instead, not this one.

### `shell_from_network_daemon` — base 50 · T1059.004
A shell (`sh`, `bash`, `dash`, …) whose ancestry contains a **web or database**
daemon (nginx, apache, php-fpm, mysqld, postgres, …) — the classic webshell /
command-injection shape.

- **sshd is deliberately excluded:** spawning a login shell is exactly its job, so
  `sshd → bash` is a login, not an intrusion. Encoding that distinction is the
  difference between a useful detection and one that fires on every SSH session.
- **Trigger:** a request to a vulnerable app that runs `system("/bin/sh")`.
- **False positives:** CGI scripts, deploy hooks, and health checks that shell out
  from a web server. Baseline the specific parent→shell pairs.
- **Matched by identity or by name.** A daemon in the ancestry counts if its
  executable is a known daemon binary by `(device, inode)`, **or** if its `comm`
  looks like one. The two halves cover different gaps: identity catches a
  compromised nginx that renamed itself before spawning the shell, and the name
  catches shebang-script daemons like `gunicorn` and `uwsgi`, whose mapped
  executable is really the Python interpreter.
- **Names may accuse, never exonerate.** Consulting `comm` is safe *here* because
  a match only ever raises a signal — a process falsely called `nginx` accuses
  itself. The mirror image, where a name suppresses a signal, is not permitted
  anywhere; see `credential_store_read`.
- **Evasions:** a payload that is not a recognized shell binary (a custom
  interpreter, a statically-linked tool) is not matched by name; the daemon table
  is also not exhaustive.

### `exec_from_tmp` — base 20 · T1036
Execution from a world-writable / volatile directory (`/tmp`, `/dev/shm`,
`/var/tmp`). Low on its own; earns weight in combination.

- **Trigger:** `cp /bin/id /tmp/x && /tmp/x`
- **False positives:** build systems, test runners, and installers execute from
  `/tmp` constantly. Intentionally low and baseline-friendly.
- **Evasions:** execute from any other attacker-writable directory not on the list
  (a writable app directory, `$HOME`).

## Credential access

### `ptrace_attach` — base 30 · T1055.008
One process attaches to another via `ptrace`, at `ptrace_access_check`. Also fires
on `/proc/<pid>/mem` reads (which take the same access check).

- **Trigger:** `gdb -p <pid>` / `strace -p <pid>` on another process.
- **False positives:** debuggers, `strace`, crash handlers, and some profilers.
- **Evasions:** in-kernel filtering drops same-uid introspection, so a same-uid
  read is not reported (see below) — an attacker operating entirely within one
  uid's processes is quieter here.

### `cross_uid_proc_read` — base 25 · T1003, T1552
A read of **another user's** process memory — the credential-theft shape. Reads of
a process in your *own* lineage (e.g. `sudo` inspecting the shell that launched it)
are suppressed; theft is reaching *outside* your tree.

- **Trigger:** as an unprivileged user, read `/proc/<root-pid>/environ`.
- **False positives:** monitoring agents and `ps`-like tools that legitimately read
  across uids. Baseline them, from a capture where they recur. **Measured:** on one desktop over 2.3
  hours this fired 7 times, 6 of them `/usr/bin/pidof` — reading another user's
  `/proc/<pid>/cmdline` goes through `ptrace_may_access`, so the ptrace sensor
  sees it. None reached the alerting floor. See docs/PERFORMANCE.md.
- **Evasions:** same-uid reads are filtered in-kernel to kill the systemd/runc
  introspection flood — so a root attacker reading another *root* process's
  `environ`/`maps` is not flagged (a `/proc/pid/mem` read still is, as it uses
  ATTACH-mode credentials). Documented trade: missing a same-priv read is
  preferable to the alert flood that filtering removes.

### `credential_store_read` — base 30 · T1003.008
### `ssh_private_key_read` — base 35 · T1552.004

A **read** of `/etc/shadow` or `/etc/gshadow` (30), or of an SSH **private** key —
`/etc/ssh/ssh_host_*`, `~/.ssh/id_*` (35). Writing those files is tampering and is covered by
`sensitive_write`; reading them is theft, and until now was invisible: watches were write-only, so a
read was filtered in-kernel and the daemon never saw it.

- **Signal ids:** **`credential_store_read`** (30) for `/etc/shadow` and `/etc/gshadow`;
  **`ssh_private_key_read`** (35) for SSH private keys.
- **Trigger:** `sudo cat /etc/shadow`, or `cat ~/.ssh/id_ed25519` as another user.
- **`ssh` reading your own private key is indistinguishable from theft** at the
  moment of the read — only what happens next separates them, which is why this
  scores below the floor rather than alerting. Measured at 2 occurrences in 2.3
  hours of desktop use, neither reaching the floor.
- **Deliberately below the alerting floor.** Reading `/etc/shadow` is what authentication *is*, so on
  its own this must not alert; it earns weight only in a lineage with something else. The same
  discipline as `privilege_escalation`: a signal that fires during normal operation cannot be allowed
  to alert alone.
- **False positives:** every authentication path reads the credential store. The obvious readers —
  `unix_chkpwd`, `sshd`, `sudo`, `su`, `login`, `passwd`, `systemd-logind`, `polkitd`, `sssd` and
  friends — are suppressed, but only when the reader's **executable** is one of those programs,
  matched by `(device, inode)`. Backup agents, config management, and vulnerability scanners will
  still fire; baseline them from a capture spanning normal operation.
- **Suppression is by file identity, never by name.** This previously matched `comm`, which the
  process itself sets: `prctl(PR_SET_NAME, "sshd")`, or a copy of `cat` at `/tmp/sudo`, produced no
  signal at all. The stated reason for accepting that was that path matching would not survive the
  `/proc` bootstrap for processes older than the agent — which is no longer true: the bootstrap
  stats `/proc/<pid>/exe`, so a pre-existing `sshd` is identified the same way a freshly exec'd one
  is. The regression scenario is `tests/scenarios/credential_read_name_spoof.sh`.
- **When identity cannot be resolved, the signal fires.** A credential reader installed somewhere
  the table does not list is simply not recognised, and its reads alert. The failure direction is
  noise, never silence — `run` prints which programs it could not find at startup so the gap is
  visible rather than discovered from an alert.
- **Evasions:** an attacker who can write to `/usr/bin` can replace a real authentication binary,
  but that requires privileges that already defeat this detection by other means. Reading a
  credential file through a hard link, a bind mount, or a copy made earlier is not matched, since
  the *watch* is still on the path — only the suppression is identity-based.
  Only `/etc/shadow`, `/etc/gshadow` and SSH private keys are read-watched; `authorized_keys` is not,
  because it is read on every single login.

## Persistence & files

### `sensitive_write` — base 20–40 · T1543, T1098
A write to a watched path, filtered in-kernel by an LPM trie so the daemon never
sees the firehose of unrelated opens. Scored by target:

| Target | Score | Meaning |
|---|---|---|
| `/etc/ld.so.preload` | 40 | dynamic-linker hijack (T1574.006) |
| `~/.ssh/authorized_keys` | 35 | SSH key persistence (T1098.004) |
| `/etc/sudoers*`, `/etc/shadow` | 35 | credential/authz tampering |
| `/etc/cron*`, systemd units | 30 | scheduled/service persistence |
| other watched path | 20 | |

The signal id in an incident names the variant, not the family, so an alert reads
`ldso_preload_write` rather than `sensitive_write`. The ids are
**`ldso_preload_write`** (40), **`authorized_keys_write`** (35),
**`cred_config_write`** (35, sudoers and shadow), **`persistence_write`** (30, cron and
systemd units) and **`sensitive_write`** (20, any other watched path — `/etc/passwd`,
`/root/.ssh/`). Searching the docs for the id in front of you should find it.

- **Trigger:** `echo /tmp/evil.so > /etc/ld.so.preload`
- **False positives:** package upgrades rewrite systemd units and cron; `ssh-copy-id`
  writes `authorized_keys`; `visudo` writes sudoers. Baseline the writing binary, learning from a capture where it writes more than once.
- **Evasions:** the watch list is a fixed prefix set — a persistence mechanism not
  on the list (a new systemd path, a shell rc file, a PAM config) is not watched.
  Per-user `authorized_keys` is covered only for existing `/home/*` and `/root` at
  startup.

### `module_load` — base 50 · T1547.006
A kernel module is loaded, detected at `do_init_module` (the real module name,
read after parsing — not an attacker-supplied filename).

- **Trigger:** `modprobe dummy` (a harmless, reversible standard module)
- **Kernel autoloads are separated out.** `request_module` runs modprobe from a kernel worker when
  a subsystem needs a driver — the first container start after a boot pulls in `veth` and
  `nf_conntrack_netlink` this way, and at full weight each was a MEDIUM incident, two alerts at the
  alerting floor from `docker run`. Those lineages root at `kthreadd` and contain a `kworker`; a
  person loading a module has a shell in their ancestry. The kernel-initiated case is reported as
  **`module_autoload`** at base 10, so it stays in the record and in `investigate` but can never
  alert alone. Same reasoning that excludes `sshd` from `shell_from_network_daemon`.
- **Evasion, deliberately accepted:** an attacker can *trigger* an autoload — creating an unusual
  socket type, say — and that load is reported as `module_autoload` rather than `module_load`. But
  the module the kernel pulls in is a legitimate one already on disk; getting attacker code into
  the kernel still means a userspace load, which keeps its full weight.
- **False positives:** hosts load modules during normal operation — hardware
  hotplug, filesystem mounts, `systemd-modules-load` at boot. A lone module load
  is **medium**, so this is a real source of alert volume; the fix is baselining
  the per-host normal set of modules. Kept high deliberately: missing a rootkit
  load is worse than a noisy alert.
- **Evasions:** an attacker who already disabled module-signature enforcement or
  who uses a kernel exploit instead of a module leaves no `do_init_module` event.

## Container

### `runtime_socket_access` — base 25 (host) / 60 (container) · T1611
A process connects to the Docker or containerd control socket
(`/var/run/docker.sock`, `/run/containerd/*.sock`), at `socket_connect`. A process
that can talk to the runtime socket can create a privileged container and escape
to the host.

- **Context is the signal:** the host `docker` CLI connects here routinely (score
  25, baseline territory), but a **containerized** process reaching the host
  runtime socket *is the escape* (score 60).
- **Trigger (host):** `docker ps`. **Trigger (escape):** a container with
  `-v /var/run/docker.sock:/var/run/docker.sock` running a `docker` client.
- **False positives:** host container tooling (docker CLI, compose, portainer).
  Baseline or expect these on any host that runs containers.
- **Evasions:** the in-kernel name match targets `docker.sock` / `containerd.sock`;
  a differently-named runtime socket, or talking to the runtime over a TCP
  endpoint instead of the unix socket, is not matched.

### `kernel_escape_hatch_write` — base 45 (host) / 75 (container) · T1611, T1543

A write to a file whose contents the kernel later executes **as root on the host**:
`/proc/sys/kernel/core_pattern`, `/proc/sys/kernel/modprobe`, `poweroff_cmd`,
`/sys/kernel/uevent_helper`, `binfmt_misc/register`.

- **Context is the signal.** On a host this is persistence. From inside a container it is an
  *escape*, because the program the kernel runs lands outside the namespace that asked for it —
  hence the much higher score.
- **Trigger:** `echo '|/tmp/x' > /proc/sys/kernel/core_pattern` (as root; revert afterwards).
- **False positives:** crash handlers legitimately set `core_pattern` — systemd-coredump, apport,
  and container runtimes configuring a host. Baseline the writing binary, from a
  capture where it does so repeatedly.
- **Matched by file identity, not path.** An escape bind-mounts the host's `/proc` elsewhere, and the
  kernel reports the path as seen in the *writer's* mount namespace — so a watched prefix never
  matches. Keying on `(dev, inode)` catches it however it is reached, and correctly distinguishes a
  container writing the *host's* `core_pattern` from one writing its own (different superblock).
  This was found by a live test after a prefix-watched version silently failed to detect or block a
  real `docker run -v /proc:/hostproc` escape.
- **Evasions:** the cgroup `release_agent` escape (CVE-2022-0492) is **not** watched. It lives at a
  variable path under `/sys/fs/cgroup/`, and the trie is prefix-based, so covering it would mean
  watching the entire cgroup tree — which systemd writes to constantly. Recognised if such a path
  reaches the detector another way, but not actively watched. `binfmt_misc` can also be reached by
  mounting it fresh rather than writing the existing register file.

### `namespace_escape` — base 70 · T1611

A process whose cgroup says it belongs to a container, executing in the **host's mount namespace** —
what having escaped looks like from the outside.

- **Scoped to the mount namespace on purpose.** `--net=host` and `--pid=host` are ordinary
  configuration; every CNI plugin and monitoring sidecar uses them, so flagging those would bury the
  signal in normal Kubernetes. There is no everyday reason to share the host's *mount* namespace:
  that is the one that hands over the filesystem.
- **Trigger:** `docker run --rm -v /:/host --pid=host --privileged alpine nsenter -t 1 -m -- sh`
- **False positives:** deliberately privileged tooling — node-level agents, some CI runners, and
  debug containers started with `nsenter` — are structurally identical to the attack. Baseline them.
- **Evasions:** requires the host's own namespace inode to be known, which is read once from
  `/proc/1/ns/mnt` at startup; an agent that cannot read it (unprivileged) disables the detection
  rather than guessing, and **a replayed capture never fires it** because the recording does not
  carry the host's namespace. Namespaces are read at `exec`, so a process that calls `setns` and
  never execs again is not seen — the escape is caught when it runs something, not when it moves.

---

## Cross-cutting limitations

- **Detect-only by default.** The LSM hooks return 0 unless `--enforce` is given, and enforcement
  covers exactly one case: escape-hatch writes from a non-host mount namespace. Every uncertain
  path fails open, denial refuses to arm without a known host namespace, and `--enforce audit`
  reports what would be blocked without blocking it.
- **Baseline is host-specific and time-bounded.** It learns from a clean capture;
  an attack present during learning is learned as normal. Learn on a known-good
  host/window.
- **Path resolution is best-effort.** Mount namespaces, bind mounts, and overlayfs
  complicate it; events carry `(dev, inode)` alongside paths for future
  re-resolution.
- **Sensor tampering is attested, not assumed.** The heartbeat proves the agent process is alive; it
  does not prove the sensors are attached, and root with `CAP_BPF` can detach a BPF link from under a
  running process. The agent therefore execs a child each interval and checks its own sensors observed
  it — if they did not, the heartbeat reports `sensors_verified: false` and the panel shows the host
  as **reporting but blind**, ranked above every other unhealthy state. An agent that looks healthy
  and sees nothing is worse than one that is visibly dead.
- **A root attacker can unload the sensors.** This is a detection tool, not a
  rootkit defense. An attacker with `CAP_BPF` can tamper with eBPF — which is
  exactly why gaining `CAP_BPF` is itself a scored escalation signal.
- **False positives are the ongoing work.** Package managers, `sudo`, systemd,
  container runtimes, and CI all do "suspicious" things constantly. Baselining by
  `(signal, executable)` is the first line; richer per-lineage baselining is future
  work.
