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
    const CAP_BPF: u64 = 1 << 38;
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
        EventType::FileOpen => sensitive_write(ev, key),
        EventType::Module => module_load(ev, key),
        EventType::Exec => {
            let mut sigs = exec_from_suspicious_dir(ev, key, graph);
            sigs.extend(shell_from_network_daemon(ev, key, graph));
            sigs
        }
        _ => Vec::new(),
    }
}

fn suid_create(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![Signal::new(
        "suid_create",
        45,
        &["T1548.001"],
        key,
        ev.ts_ns,
        format!("created a new {} binary {}", ev.gained_bits(), ev.filename),
    )]
}

fn fileless_exec(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![Signal::new(
        "fileless_exec",
        45,
        &["T1620"],
        key,
        ev.ts_ns,
        format!("executed from {} ({})", ev.exec_source(), ev.filename),
    )]
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

    vec![Signal::new("privilege_escalation", 40, &["T1068"], key, ev.ts_ns, detail)]
}

fn setcap(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![Signal::new(
        "setcap",
        40,
        &["T1548"],
        key,
        ev.ts_ns,
        format!("set file capabilities on {}", ev.filename),
    )]
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

fn sensitive_write(ev: &Event, key: ProcKey) -> Vec<Signal> {
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

fn module_load(ev: &Event, key: ProcKey) -> Vec<Signal> {
    vec![Signal::new(
        "module_load",
        50,
        &["T1547.006"],
        key,
        ev.ts_ns,
        format!("loaded kernel module {}", ev.filename),
    )]
}

/// Execution of a binary from a world-writable / volatile directory. Lower base
/// score: legitimate software does this too, so it earns its weight only in
/// combination.
fn exec_from_suspicious_dir(ev: &Event, key: ProcKey, _graph: &ProcessGraph) -> Vec<Signal> {
    let f = &ev.filename;
    if f.starts_with("/tmp/") || f.starts_with("/dev/shm/") || f.starts_with("/var/tmp/") {
        vec![Signal::new(
            "exec_from_tmp",
            20,
            &["T1036"],
            key,
            ev.ts_ns,
            format!("executed from a volatile directory: {f}"),
        )]
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
    const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "fish", "csh", "tcsh"];
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
