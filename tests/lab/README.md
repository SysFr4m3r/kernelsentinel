# kernelsentinel Docker lab

A disposable container for exercising the sensors against real post-exploitation
behavior, without running destructive commands on your dev host.

## Why a container is enough (mostly)

Docker shares the host kernel. The eBPF sensors run on the host, so they observe
the container's syscalls directly — there is nothing to install inside the
container. What the container *does* isolate is the blast radius: a SUID binary,
an `/etc/ld.so.preload` write, or a `ptrace` all stay inside its filesystem and
PID namespace.

**One exception: kernel module loading.** `insmod` in a container loads into the
host's running kernel — there is no boundary for that. Module-load scenarios
belong in a VM, never here.

## Use

```bash
tests/lab/run.sh build
```

Terminal 1 — the daemon, on the host:

```bash
sudo ./target/debug/kernelsentinel run
```

Terminal 2 — an attack, in the lab:

```bash
tests/lab/run.sh run 'cp /bin/sh /tmp/.x && chmod u+s /tmp/.x && /tmp/.x -c id'
```

The daemon, watching from the host, sees the container's exec and credential
events with a distinct cgroup id.

## Safety model

The runner starts every container with `--cap-drop=ALL`, `no-new-privileges`,
`--network none`, and pid/memory limits. A scenario that genuinely needs a
capability requests it explicitly, which documents what the attack requires:

```bash
KS_CAPS=SYS_PTRACE tests/lab/run.sh run './ptrace_scenario.sh'
```

Never used here: `--privileged` (a host compromise in one flag), and never a
bind mount of the real `/var/run/docker.sock` (that mount *is* the container
escape the socket detection is meant to catch — bind a dummy socket instead).
