# Changelog

Notable changes per release. Dates are release dates; the detail behind each
line is in the commit history.

## v0.4.0 — unreleased

### A SUID binary created already-SUID is now caught

`suid_create` watched `path_chmod` for the transition `0 → S_ISUID`, so a file
that arrives with the bit already set never fired it. That was documented as a
known evasion; measured, the note was wrong in both directions.

`cp -p` **is** caught — `cp` calls `fchmod` internally and reaches the same
hook, so listing it as an evasion overstated the gap. `open("/tmp/.x", O_CREAT,
04755)` was **not** caught, and produced no event of any kind: a setuid-root
binary landing on a host with nothing to show for it.

A twelfth sensor, `lsm/path_mknod`, closes that. It sees the mode a file is
about to be created with, filters on the setuid bits in-kernel, and reports the
creation as a gain from nothing — so the existing detector needed no change. It
reports the file name rather than the full path, because `bpf_d_path` is refused
on that hook.

Two scenarios hold both routes down, and a third covers `rename` into place.

## v0.3.3 — unreleased

### The agent-keys file is checked before it is trusted

`agents.keys` holds the fleet's ingest credentials in plaintext, and a key is all
it takes to write incidents as that host. Its permissions were never checked, so
a world-readable file handed every local account the ability to forge any host's
telemetry — and nothing downstream can tell a forged incident from a real one
afterwards.

The server now refuses to start on a world-readable keys file, and warns on a
group-readable one. Refused rather than warned on the same test used for
enforcement: continuing does active harm rather than leaving a gap, and the fix
is one `chmod`, named in the message.

Two hosts sharing a key is also refused now, with the line number. The map kept
one host, and every incident from the other was filed under that name with
nothing to indicate it. One host holding several keys is still allowed — that is
how a key rotation happens without a window where the agent cannot ship.

### Privilege escalation through a username

A session token's payload is `username|role|expiry`, signed and then split on
`|`. Usernames were only checked for being non-empty, so an account named
`mallory|admin|99999999999` produced a five-field payload — and reading the
first three fields took the *username's* second field as the role and its third
as the expiry.

An account issued as `viewer` for eight hours validated as **`admin` until the
year 5138**, on a signature the server had genuinely produced. Nothing about the
token was forged, so no signature check could notice.

Creating a user requires an admin, so this is not reachable by an unprivileged
account on its own — but "an admin creates an account using a name the requester
supplied" is an ordinary workflow, and the result is that person holding admin
permanently.

Fixed in two independent places. Token payloads must have exactly three fields,
which also protects a database that already contains such a user, since the
restriction below cannot retroactively rename one. And usernames are now limited
to letters, digits and `. _ - @ +`, up to 64 characters.

**If you run the fleet server with multiple accounts, check your user list for a
username containing `|`.**

### Release drift is a test failure

Twice a release was tagged, work continued, and the new entries were written
under the tagged heading — describing a version that does not contain them. The
second time the tag was already published. A test now refuses that state: if the
version in `Cargo.toml` is already tagged, `HEAD` must *be* that tag, and the
newest changelog section must name the version being built.

The practical effect is that the first commit after a release bumps the version
and opens a section. That is stricter than most projects, and deliberately so —
the alternative kept producing a changelog that described releases inaccurately.

## v0.3.2 — two paths from a monitored host to the server

**Upgrade if you run the fleet server.** Both fixes below are reachable from
outside its trust boundary, and `SECURITY.md` scopes exactly that.

### Stored XSS from a monitored host to the admin's browser

The panel receives the incident record a host sent, verbatim — the server keeps
it raw and adds only `_id` and the triage fields. String fields were escaped
after an earlier XSS, but the numeric ones never were, because nobody thinks of
a score as text.

```json
{"severity":"HIGH","score":"<img src=x onerror=…>","subject":{"pid":"<img …>"}}
```

`<span class="badge">${d.score}</span>` put that straight into `innerHTML`,
running script in the authenticated session of whoever opened the panel — a path
from one compromised monitored host to the operator who is investigating it, and
from there to every other host's data.

Every numeric field an incident carries is now coerced with `Number()` rather
than escaped, which is stronger: a number cannot carry markup at all. A test
scans the shipped page for any incident field reaching `innerHTML` without
escaping or coercion, so the next field nobody thinks of as text fails the build
instead of shipping.

Severity also now maps through a whitelist before it reaches a CSS variable, so
a hostile value cannot walk the prototype chain into a style attribute.

### Request bodies are bounded

Every body the server read was unbounded. `read_to_string` on the request reader
allocates whatever arrives, and two of those five endpoints sit outside the
server's trust boundary: `/api/ingest`, reachable by any monitored host holding
an agent key, and `/api/login`, reachable by anyone who can reach the panel at
all — before a credential is checked, and before the login limiter has a failure
to count, so the lockout does not help.

SECURITY.md puts "anything that lets a compromised monitored host affect the
server" explicitly in scope, and this was it. Bodies are now capped at 8MiB on
ingest and 64KiB on the form endpoints, rejected with 413.

The cap binds on bytes actually read, not on `Content-Length`: that header is
supplied by the caller and absent entirely on a chunked body, so it is an early
exit and never the limit.

### "Baseline them" now has a test, and needed a correction

`docs/DETECTIONS.md` answered a known false positive with *baseline them* in
seven places, and following that literally suppressed nothing. A pair seen once
keeps ~85% of its score — deliberately, so an attacker resident during a "clean"
recording cannot whitelist themselves with one action — but the documentation
never said the activity has to **recur** in the capture. An operator following
the advice would have concluded baselining was broken.

The docs now lead with what the advice requires. A noise scenario verifies it
end to end: config-management writes to `/etc/cron.d` and `/etc/sudoers.d` are
recorded, learned from, and the same activity must then be silent. Eight alerts
at the operational floor without a baseline, zero with one.

The test also fails if the activity was quiet *without* a baseline, because a
scenario that is quiet either way is not exercising a false positive at all.

## v0.3.1 — enforcement stops announcing a control it cannot apply

**Upgrade if you run `--enforce on` anywhere.** In v0.3.0 and earlier it
reported that escape-hatch writes would be denied whether or not the sensor that
denies them was alive.

### `--enforce on` no longer claims a control it cannot apply

Denial is implemented by the `file_open` program returning `-EPERM`. On a kernel
where that program is inert, nothing can be blocked — and the agent printed
"kernel escape-hatch writes from outside the host mount namespace will be
denied" regardless.

That is the worst assurance this tool could give. The sensor count was a
monitoring gap; this was a security control that existed only in the line
announcing it, with an operator who armed it and stopped worrying. Enforcement
now disarms itself when `file_open` is not active, rewrites the policy map to
off so nothing downstream reads a policy that cannot be applied, and says so.

It does not refuse to start, unlike the unknown-host-namespace case, because the
failure modes differ in kind: an unknown namespace risks denying *on the host*,
which is actively harmful, while an inert sensor risks not denying, which is a
gap — and refusing to start would also discard the five sensors that do work.

### The panel shows how much of a host the agent can see

Attestation answers whether an agent can see *anything* — it execs a child every
heartbeat and checks its own sensors observed it. But the canary speaks only for
`exec`, so a host with six inert sensors passed it and rendered as an
unqualified green. That is the ordinary state wherever BPF-LSM is compiled in
but not enabled, and an operator scanning a fleet had no way to see it.

The heartbeat now carries how many sensors can observe an event and how many
exist, and the fleet view shows `5/11 sensors` beside a live host, with a banner
on the host page naming the detections that cannot fire there. The badge is
silent when a host is fully covered, so it means something when it appears.

Coverage is deliberately not folded into the status: a partially covered host is
not "blind", its agent is reporting and its exec sensor works, and conflating
the two would either understate a detached agent or overstate a limited one.

Server schema goes to v3, migrated in place so history is kept. An agent too old
to report coverage sends zeros, and those do not overwrite a known count.

## v0.3.0 — the agent stops overstating what it can see

**Upgrade from v0.2.1, especially on Ubuntu, Debian or RHEL.** On those hosts
v0.2.1 reported `11 of 11 sensors attached` while six of them saw nothing.

### The agent no longer counts sensors that cannot fire

A BPF-LSM program attaches whether or not `bpf` is in `/sys/kernel/security/lsm`
— the kernel accepts it either way, and only the hook being *invoked* depends on
that list. Every distribution that ships `CONFIG_BPF_LSM=y` without enabling it
therefore ran an agent that claimed full coverage and had none of the file,
credential-theft, fileless-exec or container-socket detections.

Measured on a GitHub runner rather than reasoned about: eleven programs
attached, a real exec produced an event, a real `chmod u+s` and a real read of
`/etc/shadow` produced nothing at all. The agent now reads the LSM list at
startup and reports `5 of 11 sensors active` there, naming the six and why. The
count says *active* rather than *attached*, because "attached" describes a
syscall's return value, not a sensor doing its job.

Nothing is lost that your host ever had. What changes is that the report is
true. If you run on a distribution where BPF-LSM is compiled in but inactive,
`docs/COMPATIBILITY.md` has the one-line boot parameter that turns it on.

`doctor` also stopped claiming those sensors "fall back to kprobes". There is no
kprobe fallback and there never was.

### Suppression by file identity, not by process name

`credential_read` suppressed the programs whose job is authentication by
matching `comm`, which the process itself chooses. `cp /bin/cat /tmp/sudo &&
/tmp/sudo /etc/shadow` produced no signal at all — not a reduced score, nothing.

Suppression now requires the reader's executable to *be* one of the host's
authentication binaries, matched by `(device, inode)` and resolved at startup.
`shell_from_network_daemon` gains the same identity check while keeping its name
test, because the asymmetry matters: a name that suppresses a signal is a
one-line bypass, a name that raises one only ever accuses a liar of its own
behaviour. Names may accuse, never exonerate.

### Baselines carry evidence instead of a verdict

A `(signal, exe)` pair seen once during learning used to be normal forever, at
10% score. An attacker resident while you recorded a "clean" capture whitelisted
themselves with a single action, and a looped payload was indistinguishable from
a habit.

Suppression is now proportional to the evidence behind it: how many times a pair
was seen, how much of the learning window it spanned, and how long ago the
baseline was learned. One sighting keeps ~85% of its score. A burst confined to
one instant caps at half confidence however often it repeated. A baseline decays
after 14 days and suppresses nothing past 90. Every one of those fails toward
alerting.

Existing baseline files still load. They carry no timestamps, so every entry
reads as one burst of unknown age — weaker than before, and the startup line
says so. Re-learn from a capture spanning hours.

### `budget` — measure the alert volume

```bash
kernelsentinel record --out normal-day.ndjson
kernelsentinel budget --capture normal-day.ndjson
```

Record a host doing ordinary work and every incident in that capture is a false
positive by construction. Reports incidents at each severity floor, what caused
them, and what a baseline removed. First measurement, on a desktop over 2.3
hours: zero alerts at the default floor.

### A verifier rejection that only one compiler produced

`handle_file_open` used a null map pointer to mean "no match", which clang may
compile into `ptr &= mask` — an instruction the verifier rejects outright.
Whether it did depended on the compiler, so the same source built a loadable
object on one machine and an unloadable one on another. Published releases were
not affected; a runner image bump would eventually have made them so.

### Verification

CI now loads the BPF object into a kernel, which it had never done — that is how
both the verifier rejection and the false attach count were found. It attaches
on x86_64 and aarch64, and boots the runner's own kernel under QEMU with
`lsm=...,bpf` appended so the six BPF-LSM sensors are exercised somewhere other
than a developer machine. The release pipeline refuses to publish an agent that
cannot attach.

`COMPATIBILITY.md` may now mark a row "verified" only when a probe actually ran
there and its output is recorded, enforced by a test.

## v0.2.1 — fixes a container escape detection that did not work

**Upgrade from v0.2.0.** In v0.2.0 the kernel escape-hatch detection matched on
file *paths*, and a container escape defeats that by construction: it
bind-mounts the host's `/proc` somewhere else, and the kernel reports the path
as seen in the writer's own mount namespace. A textbook escape —

```
docker run --privileged -v /proc:/hostproc alpine \
  sh -c 'echo "|/tmp/x" > /hostproc/sys/kernel/core_pattern'
```

— was neither detected nor blocked, and `--enforce on` therefore gave false
confidence against precisely the attack it advertised.

Escape hatches are now identified by `(dev, inode)`, so the file is recognised
however it is reached. This also correctly distinguishes a container writing the
*host's* `core_pattern` from one writing its own, which no path comparison can.

Verified by re-running the same attack: the write fails with `Operation not
permitted`, the incident is recorded as `BLOCKED:` at 83/100, and the host's
`core_pattern` is unchanged.

Nothing else changed. If you installed v0.2.0, upgrade.

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
