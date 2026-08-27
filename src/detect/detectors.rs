//! Built-in detections. Each maps a single event to zero or more signals; the
//! engine handles combining them across a lineage. These are the individually-
//! meaningful observations -- the interesting behavior emerges when several
//! land in one process chain.

use crate::decoded::Event;
use crate::event::EventType;
use crate::graph::{ProcKey, ProcessGraph};

use super::signal::Signal;

/// Dangerous capabilities whose *gain* is a privilege-escalation signal on its
/// own, independent of a uid change.
const DANGEROUS_CAPS: u64 = {
    const CAP_SYS_ADMIN: u64 = 1 << 21;
    const CAP_SYS_MODULE: u64 = 1 << 16;
    const CAP_SYS_PTRACE: u64 = 1 << 19;
    const CAP_BPF: u64 = 1 << 39;
    const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
    CAP_SYS_ADMIN | CAP_SYS_MODULE | CAP_SYS_PTRACE | CAP_BPF | CAP_DAC_READ_SEARCH
};

pub fn detect(ev: &Event, graph: &ProcessGraph) -> Vec<Signal> {
    let key = ProcKey {
        pid: ev.tgid,
        start_boottime: ev.start_boottime,
    };
    match ev.event_type() {
        EventType::FileMode => suid_create(ev, key),
        EventType::ExecAnon => fileless_exec(ev, key),
        EventType::CredChange => privilege_escalation(ev, key),
        EventType::Setcap => setcap(ev, key),
        EventType::Ptrace => ptrace(ev, key, graph),
        EventType::FileOpen => {
            if ev.opened_for_write() {
                sensitive_write(ev, key)
            } else {
                credential_read(ev, key, graph)
            }
        }
        EventType::Module => module_load(ev, key, graph),
        EventType::SockConnect => privileged_socket(ev, key),
        EventType::Exec => {
            let mut sigs = namespace_escape(ev, key, graph);
            sigs.extend(exec_from_suspicious_dir(ev, key, graph));
            sigs.extend(shell_from_network_daemon(ev, key, graph));
            sigs
        }
        _ => Vec::new(),
    }
}

fn suid_create(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![
        Signal::new(
            "suid_create",
            45,
            &["T1548.001"],
            key,
            ev.ts_ns,
            format!("created a new {} binary {}", ev.gained_bits(), ev.filename),
        )
        .with_target(&ev.filename),
    ]
}

fn fileless_exec(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![
        Signal::new(
            "fileless_exec",
            45,
            &["T1620"],
            key,
            ev.ts_ns,
            format!("executed from {} ({})", ev.exec_source(), ev.filename),
        )
        .with_target(format!("/proc/{}/exe", key.pid)),
    ]
}

fn privilege_escalation(ev: &Event, key: ProcKey) -> Vec<Signal> {
    // A single commit_creds is ONE transition: becoming root and gaining the
    // capabilities that come with it are the same event, not two independent
    // reasons to worry. Emitting both would make an ordinary `sudo` -- which
    // legitimately does both -- chain to a false critical. So this detector
    // emits at most one signal, scored so that a bare escalation lands LOW and
    // is suppressed on its own; it only matters in combination with another
    // signal in the lineage (a SUID creation, a fileless exec, ...).
    let to_root = ev.old_euid != 0 && ev.euid == 0;
    let gained = ev.cap_effective & !ev.old_cap_effective & DANGEROUS_CAPS;

    if !to_root && gained == 0 {
        return Vec::new();
    }

    let mut detail = String::new();
    if to_root {
        detail.push_str(&format!("changed euid {} -> 0", ev.old_euid));
    }
    if gained != 0 {
        let names = crate::event::cap_names(gained).join(",");
        if !detail.is_empty() {
            detail.push_str("; ");
        }
        detail.push_str(&format!("gained {names}"));
    }

    vec![Signal::new(
        "privilege_escalation",
        40,
        &["T1068"],
        key,
        ev.ts_ns,
        detail,
    )]
}

fn setcap(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![
        Signal::new(
            "setcap",
            40,
            &["T1548"],
            key,
            ev.ts_ns,
            format!("set file capabilities on {}", ev.filename),
        )
        .with_target(&ev.filename),
    ]
}

fn ptrace(ev: &Event, key: ProcKey, graph: &ProcessGraph) -> Vec<Signal> {
    if ev.ptrace_is_attach() {
        return vec![Signal::new(
            "ptrace_attach",
            30,
            &["T1055.008"],
            key,
            ev.ts_ns,
            format!("ptrace-attached to pid {}", ev.target_pid),
        )];
    }

    // A cross-uid read of a process *in your own lineage* is not credential
    // theft -- it is a parent/child relationship, e.g. sudo (now root) reading
    // the tty of the shell that launched it. The theft signal is reading a
    // process OUTSIDE your tree. Suppress in-lineage reads.
    let in_lineage = graph
        .ancestry(&key)
        .iter()
        .any(|n| n.key.pid == ev.target_pid);
    if in_lineage {
        return Vec::new();
    }

    vec![Signal::new(
        "cross_uid_proc_read",
        25,
        &["T1003", "T1552"],
        key,
        ev.ts_ns,
        format!("read an unrelated process's memory (pid {})", ev.target_pid),
    )]
}

/// Programs whose whole job is to read the credential store. Every
/// authentication on the host goes through one of these, so without this the
/// signal would fire dozens of times a day on a machine where nothing happened.
/// Matched on `comm`, which is what the kernel gives us here.
const CREDENTIAL_READERS: &[&str] = &[
    "unix_chkpwd",
    "sshd",
    "sudo",
    "su",
    "login",
    "passwd",
    "chpasswd",
    "gpasswd",
    "newgrp",
    "usermod",
    "useradd",
    "userdel",
    "vipw",
    "systemd-logind",
    "polkitd",
    "sssd",
    "agetty",
    "gdm-session-wor",
    "lightdm",
    "accounts-daemon",
];

/// A read of the credential store or of an SSH private key -- the theft shape,
/// as opposed to the tampering shape `sensitive_write` covers.
///
/// Deliberately scored below the alerting floor. Reading /etc/shadow is what
/// authentication *is*, so on its own this is noise; it earns its weight only
/// when it appears in a lineage alongside something else. That is the same
/// discipline applied to `privilege_escalation`: a signal that fires during
/// normal operation must not be able to alert by itself.
fn credential_read(ev: &Event, key: ProcKey, graph: &ProcessGraph) -> Vec<Signal> {
    let comm = graph.get(&key).map(|n| n.comm.as_str()).unwrap_or("");
    if CREDENTIAL_READERS.contains(&comm) {
        return vec![];
    }
    let (score, id, what): (u32, &'static str, &str) =
        if ev.filename.contains("ssh_host_") || ev.filename.contains("/.ssh/id_") {
            (35, "ssh_private_key_read", "an SSH private key")
        } else {
            (30, "credential_store_read", "the credential store")
        };
    vec![
        Signal::new(
            id,
            score,
            &["T1003.008", "T1552.004"],
            key,
            ev.ts_ns,
            format!("read {what}: {}", ev.filename),
        )
        .with_target(&ev.filename),
    ]
}

/// Files whose contents the kernel will execute as root on the *host*. Writing
/// one is persistence from the host and a container escape from inside one --
/// the payload runs outside the namespace that wrote it.
fn is_kernel_escape_hatch(path: &str) -> bool {
    const HATCHES: &[&str] = &[
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
        "/proc/sys/kernel/poweroff_cmd",
        "/sys/kernel/uevent_helper",
        "/proc/sys/fs/binfmt_misc/register",
        // Not watched by prefix (the cgroup tree is far too busy to watch
        // wholesale), but recognised if a path reaches us another way.
        "release_agent",
    ];
    HATCHES.iter().any(|h| path.contains(h))
}

fn sensitive_write(ev: &Event, key: ProcKey) -> Vec<Signal> {
    // A kernel escape hatch outranks everything else here, and outranks it by
    // more when the writer is containerised: the same write that is persistence
    // on a host is an escape from inside a container, because the program the
    // kernel runs lands outside the namespace that asked for it.
    // Identity first. The path is whatever the writer's mount namespace called
    // it, which for an escape is deliberately not the real one.
    if ev.escape_target || is_kernel_escape_hatch(&ev.filename) {
        // Enforcement outcome leads the detail. An operation the kernel blocked
        // reads very differently from one that succeeded, and burying that at
        // the end of a sentence is how a responder wastes an hour on an attack
        // that never landed.
        let outcome = if ev.denied {
            "BLOCKED: "
        } else if ev.would_deny {
            "would be blocked: "
        } else {
            ""
        };
        let (score, detail) = if ev.container.is_empty() {
            (
                45,
                format!("wrote {}, which the kernel executes as root", ev.filename),
            )
        } else {
            (
                75,
                format!(
                    "{outcome}container {} wrote {}, which the kernel executes as root on the \
                     host (escape)",
                    ev.container, ev.filename
                ),
            )
        };
        return vec![
            Signal::new(
                "kernel_escape_hatch_write",
                score,
                &["T1611", "T1543"],
                key,
                ev.ts_ns,
                detail,
            )
            .with_target(&ev.filename),
        ];
    }

    // Some targets are far more diagnostic than others.
    let (score, id): (u32, &'static str) = if ev.filename.contains("ld.so.preload") {
        (40, "ldso_preload_write")
    } else if ev.filename.contains("authorized_keys") {
        (35, "authorized_keys_write")
    } else if ev.filename.contains("/etc/cron") || ev.filename.contains("systemd") {
        (30, "persistence_write")
    } else if ev.filename.contains("sudoers") || ev.filename.contains("/etc/shadow") {
        (35, "cred_config_write")
    } else {
        (20, "sensitive_write")
    };
    vec![Signal::new(
        id,
        score,
        &["T1543", "T1098"],
        key,
        ev.ts_ns,
        format!("wrote to {}", ev.filename),
    )]
}

/// Was this module load initiated by the kernel rather than by a person?
///
/// `request_module` runs modprobe from a kernel worker when a subsystem needs a
/// driver -- creating a veth pair pulls in `veth`, a container's networking
/// pulls in `nf_conntrack_netlink`. Those lineages root at kthreadd and contain
/// a kworker; a person loading a module has a shell in their ancestry instead.
///
/// The same reasoning that excludes sshd from `shell_from_network_daemon`:
/// spawning a login shell is sshd's job, and pulling in a driver on demand is
/// the kernel's.
fn kernel_initiated(graph: &ProcessGraph, key: ProcKey) -> bool {
    graph
        .ancestry(&key)
        .iter()
        .any(|n| n.comm == "kthreadd" || n.comm.starts_with("kworker/"))
}

fn module_load(ev: &Event, key: ProcKey, graph: &ProcessGraph) -> Vec<Signal> {
    // Measured on real hardware: the first container start after a boot loads
    // veth and nf_conntrack_netlink, and at the full score each was a MEDIUM
    // incident -- two alerts, at the alerting floor, from `docker run`. A
    // detection that fires on the most routine container operation there is
    // gets the whole tool muted.
    //
    // Kept as a signal rather than dropped: it stays visible in `investigate`
    // and at --min-severity info, so the forensic record of every module load
    // survives. It simply cannot alert on its own, and carries a distinct id so
    // "the kernel pulled in a driver" is never confused with "someone loaded a
    // module".
    if kernel_initiated(graph, key) {
        return vec![
            Signal::new(
                "module_autoload",
                10,
                &["T1547.006"],
                key,
                ev.ts_ns,
                format!(
                    "kernel autoloaded module {} on demand (request_module)",
                    ev.filename
                ),
            )
            .with_target(&ev.filename),
        ];
    }
    vec![
        Signal::new(
            "module_load",
            50,
            &["T1547.006"],
            key,
            ev.ts_ns,
            format!("loaded kernel module {}", ev.filename),
        )
        .with_target(&ev.filename),
    ]
}

/// Execution of a binary from a world-writable / volatile directory. Lower base
/// score: legitimate software does this too, so it earns its weight only in
/// combination.
/// A containerised process running in the *host's* mount namespace.
///
/// Its cgroup says it belongs to a container, but it can see the host's
/// filesystem -- which is what having escaped looks like from the outside.
///
/// Scoped to the mount namespace on purpose. `--net=host` and `--pid=host` are
/// ordinary configuration (every CNI plugin and monitoring sidecar uses them),
/// so flagging those would bury the signal in normal Kubernetes. There is no
/// equivalent everyday reason to share the host's *mount* namespace: that is
/// the one that hands over the filesystem.
fn namespace_escape(ev: &Event, key: ProcKey, graph: &ProcessGraph) -> Vec<Signal> {
    let host = graph.host_mnt_ns();
    // 0 means the host's namespace was never recorded -- a replayed capture.
    // Guessing would be worse than staying quiet.
    if host == 0 || ev.mnt_ns == 0 || ev.container.is_empty() {
        return vec![];
    }
    if ev.mnt_ns != host {
        return vec![];
    }
    vec![
        Signal::new(
            "namespace_escape",
            70,
            &["T1611"],
            key,
            ev.ts_ns,
            format!(
                "container {} is executing in the host mount namespace (mnt_ns {host})",
                ev.container
            ),
        )
        .with_target(&ev.filename),
    ]
}

fn exec_from_suspicious_dir(ev: &Event, key: ProcKey, _graph: &ProcessGraph) -> Vec<Signal> {
    let f = &ev.filename;
    if f.starts_with("/tmp/") || f.starts_with("/dev/shm/") || f.starts_with("/var/tmp/") {
        vec![
            Signal::new(
                "exec_from_tmp",
                20,
                &["T1036"],
                key,
                ev.ts_ns,
                format!("executed from a volatile directory: {f}"),
            )
            .with_target(f),
        ]
    } else {
        Vec::new()
    }
}

/// A shell whose ancestry contains a network-facing service daemon. A web or
/// database server spawning /bin/sh is the classic webshell / command-injection
/// shape (T1059.004) -- it should essentially never happen in normal operation.
///
/// sshd is deliberately excluded: spawning a login shell is exactly its job, so
/// sshd -> bash is an interactive login, not an intrusion. Web and database
/// daemons have no such reason to fork a shell.
fn shell_from_network_daemon(ev: &Event, key: ProcKey, graph: &ProcessGraph) -> Vec<Signal> {
    if !is_shell(&ev.filename) {
        return Vec::new();
    }
    // Walk the shell's ancestry for a web/db daemon.
    let daemon = graph
        .ancestry(&key)
        .into_iter()
        .find(|n| is_web_or_db_daemon(&n.comm))
        .map(|n| format!("{}({})", n.comm, n.key.pid));

    match daemon {
        Some(d) => vec![Signal::new(
            "shell_from_network_daemon",
            50,
            &["T1059.004"],
            key,
            ev.ts_ns,
            format!("{} spawned a shell ({})", d, shell_name(&ev.filename)),
        )],
        None => Vec::new(),
    }
}

fn shell_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_shell(path: &str) -> bool {
    const SHELLS: &[&str] = &[
        "sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "csh", "tcsh",
    ];
    SHELLS.contains(&shell_name(path))
}

/// Web and database servers -- daemons that face the network but have no
/// legitimate reason to spawn a shell. sshd is intentionally absent.
fn is_web_or_db_daemon(comm: &str) -> bool {
    const DAEMONS: &[&str] = &[
        "nginx",
        "apache2",
        "httpd",
        "php-fpm",
        "php-fpm7",
        "php-fpm8",
        "tomcat",
        "node",
        "gunicorn",
        "uwsgi",
        "mysqld",
        "mariadbd",
        "postgres",
        "redis-server",
        "mongod",
        "memcached",
    ];
    DAEMONS.iter().any(|d| comm == *d || comm.starts_with(d))
}

/// Connecting to the Docker/containerd control socket. A process that can talk
/// to the runtime socket can create a privileged container and escape to the
/// host, so this is the container-escape primitive (T1611). It scores far higher
/// from inside a container -- host tooling (the docker CLI) connects here
/// routinely and is best handled by the baseline, but a *containerized* process
/// reaching the host runtime socket is the escape itself.
fn privileged_socket(ev: &Event, key: ProcKey) -> Vec<Signal> {
    let (score, detail) = if ev.container.is_empty() {
        (
            25,
            format!("connected to the container runtime socket {}", ev.filename),
        )
    } else {
        (
            60,
            format!(
                "container {} connected to the host runtime socket {} (escape primitive)",
                ev.container, ev.filename
            ),
        )
    };
    vec![Signal::new(
        "runtime_socket_access",
        score,
        &["T1611"],
        key,
        ev.ts_ns,
        detail,
    )]
}
