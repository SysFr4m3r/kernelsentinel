
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};

use kernelsentinel::clock::BootClock;
use kernelsentinel::event::{EventType, RawEvent};
use kernelsentinel::graph::{scan, ProcKey, ProcessGraph};
use kernelsentinel::{doctor, sensors};

#[derive(Parser)]
#[command(
    name = "kernelsentinel",
    about = "Runtime detection engine for Linux post-exploitation behavior",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attach the sensors and stream events.
    Run {
        /// Maximum processes held in the graph before eviction.
        #[arg(long, default_value_t = 50_000)]
        max_processes: usize,
        /// Seconds to retain a process after it exits.
        #[arg(long, default_value_t = 300)]
        retain: u64,
    },
    /// Print the current process tree as reconstructed from /proc.
    Tree {
        /// Show only this subtree.
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Report whether this kernel can run the sensors.
    Doctor,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor => {
            let report = doctor::run();
            report.print();
            if report.fatal() {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Tree { pid } => tree(pid),
        Command::Run {
            max_processes,
            retain,
        } => run(max_processes, retain),
    }
}

/// Snapshot the process tree from /proc. This exercises exactly the bootstrap
/// path the daemon uses, so `tree` diverging from `pstree` means the daemon's
/// view is wrong too.
fn tree(root_pid: Option<u32>) -> Result<()> {
    let mut graph = ProcessGraph::new(usize::MAX, Duration::from_secs(0));
    let result = scan::bootstrap(&mut graph);

    let roots = match root_pid {
        Some(pid) => graph
            .nodes()
            .filter(|n| n.key.pid == pid)
            .map(|n| n.key)
            .collect(),
        None => graph.roots(),
    };

    for root in roots {
        print_subtree(&graph, &root, "", true);
    }
    eprintln!(
        "\n{} processes ({} unreadable, normal: processes exit while /proc is walked)",
        result.scanned, result.failed
    );
    Ok(())
}

fn print_subtree(graph: &ProcessGraph, key: &ProcKey, prefix: &str, last: bool) {
    let Some(node) = graph.get(key) else { return };

    let connector = if prefix.is_empty() {
        ""
    } else if last {
        "└─ "
    } else {
        "├─ "
    };
    let cred = if node.uid != node.euid {
        format!(" [uid={}→{}]", node.uid, node.euid)
    } else if node.uid != 0 {
        format!(" [uid={}]", node.uid)
    } else {
        String::new()
    };
    println!(
        "{prefix}{connector}{} ({}){cred}",
        node.comm, node.key.pid
    );

    let children = graph.children_of(key);
    let child_prefix = if prefix.is_empty() {
        String::new()
    } else if last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}│  ")
    };
    let child_prefix = if prefix.is_empty() {
        "  ".to_string()
    } else {
        child_prefix
    };
    for (i, child) in children.iter().enumerate() {
        print_subtree(graph, child, &child_prefix, i + 1 == children.len());
    }
}

fn run(max_processes: usize, retain_secs: u64) -> Result<()> {
    let report = doctor::run();
    if report.fatal() {
        report.print();
        anyhow::bail!("preflight checks failed");
    }

    install_signal_handlers();

    let bootclock = BootClock::new();
    let self_pid = std::process::id();

    let mut graph = ProcessGraph::new(max_processes, Duration::from_secs(retain_secs));
    let boot = scan::bootstrap(&mut graph);
    status(&format!(
        "kernelsentinel: bootstrapped {} processes from /proc",
        boot.scanned
    ));

    status("kernelsentinel: sensors attached, streaming events (ctrl-c to stop)\n");
    emit(&format!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        "TIME(UTC)", "PID", "PPID", "UID", "COMM", "EVENT"
    ));

    let mut last_reap = 0u64;
    let stats = sensors::run(&STOP, |ev: RawEvent| {
        if ev.tgid == self_pid {
            return;
        }
        graph.apply(&ev);

        // Reaping on the event stream rather than a timer keeps the daemon
        // single-threaded; an idle host has nothing to reap anyway.
        if ev.ts_ns.saturating_sub(last_reap) > 10_000_000_000 {
            graph.reap(ev.ts_ns);
            last_reap = ev.ts_ns;
        }
        print_event(&bootclock, &ev);
    })?;

    let g = graph.stats();
    status(&format!(
        "kernelsentinel: graph {} nodes ({} alive), {} reaped, {} evicted, {} scanned nodes adopted",
        g.nodes, g.alive, g.reaped, g.evicted, g.adopted
    ));
    status(&format!(
        "\nkernelsentinel: {} events emitted, {} ring buffer drops",
        stats.emitted, stats.drops
    ));
    if stats.drops > 0 {
        status("kernelsentinel: WARNING — dropped events mean blind spots");
    }
    Ok(())
}

/// Write one line to stdout without panicking. `println!` unwraps its write and
/// panics on a broken pipe (reader gone); inside the ring buffer callback that
/// panic unwinds across libbpf's C stack and aborts the process. Here a broken
/// pipe just means the reader left, so signal a clean stop and move on.
fn emit(line: &str) {
    let mut out = std::io::stdout().lock();
    if out.write_all(line.as_bytes()).and_then(|_| out.write_all(b"\n")).is_err() {
        STOP.store(true, Ordering::SeqCst);
    }
}

/// Same, for status/summary messages on stderr. Never panics on a broken pipe.
fn status(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

fn print_event(clock: &BootClock, ev: &RawEvent) {
    let detail = match ev.event_type() {
        EventType::Exec => {
            let filename = ev.filename();
            let argv = ev.argv();
            // argv[0] is conventionally the program name and is already shown
            // as the filename. For shebang scripts the kernel also inserts the
            // script path as argv[1], so drop that repeat too.
            let mut args: &[String] = argv.get(1..).unwrap_or(&[]);
            if args.first().map(String::as_str) == Some(filename.as_str()) {
                args = &args[1..];
            }
            let trunc = if ev.truncated() { " …" } else { "" };
            format!("exec {} {}{}", filename, args.join(" "), trunc)
        }
        EventType::Exit => format!("exit code={}", ev.exit_code),
        EventType::Fork => format!("fork -> pid {}", ev.child_pid),
        EventType::CredChange => {
            let mut parts = Vec::new();
            if ev.old_uid != ev.uid || ev.old_euid != ev.euid {
                parts.push(format!(
                    "uid {}:{} -> {}:{}",
                    ev.old_uid, ev.old_euid, ev.uid, ev.euid
                ));
            }
            if ev.old_gid != ev.gid || ev.old_egid != ev.egid {
                parts.push(format!(
                    "gid {}:{} -> {}:{}",
                    ev.old_gid, ev.old_egid, ev.gid, ev.egid
                ));
            }
            // Report only capabilities that were *gained*; losing privilege is
            // routine (every setuid-root binary dropping caps) and not a signal.
            let gained = ev.cap_effective & !ev.old_cap_effective;
            if gained != 0 {
                let names = format_caps(gained);
                parts.push(format!("+caps {names}"));
            }
            format!("cred {}", parts.join(" "))
        }
        EventType::FileOpen => {
            let path = ev.filename();
            let mode = if ev.opened_for_write() { "write" } else { "read" };
            let label = kernelsentinel::watchlist::label_for(&path);
            format!("open[{mode}] {path}  <{label}>")
        }
        EventType::FileMode => {
            let path = ev.filename();
            let warn = if ev.degraded_path() { " [path degraded]" } else { "" };
            // Only the permission bits are meaningful to a reader here.
            format!(
                "SUID-CREATE {} gained {} (0{:o} -> 0{:o}){}",
                path,
                ev.gained_bits(),
                ev.old_file_mode & 0o7777,
                ev.file_mode & 0o7777,
                warn
            )
        }
        EventType::Setcap => {
            let warn = if ev.degraded_path() { " [name only]" } else { "" };
            format!("SETCAP file capabilities set on {}{}", ev.filename(), warn)
        }
        EventType::Ptrace => {
            let kind = if ev.ptrace_is_attach() { "ATTACH" } else { "read" };
            format!(
                "PTRACE[{kind}] -> pid {} ({})",
                ev.target_pid,
                ev.filename() // target comm, stored in the path buffer
            )
        }
        EventType::ExecAnon => {
            let warn = if ev.degraded_path() { " [path degraded]" } else { "" };
            format!(
                "FILELESS-EXEC from {} {}{}",
                ev.exec_source(),
                ev.filename(),
                warn
            )
        }
        EventType::Module => format!("MODULE-LOAD {} (via {})", ev.filename(), ev.module_origin()),
        EventType::Unknown(t) => format!("unknown type={t}"),
    };

    emit(&format!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        clock.format(ev.ts_ns),
        ev.tgid,
        ev.ppid,
        ev.uid,
        ev.comm(),
        detail.trim_end()
    ));
}

/// Set on SIGINT/SIGTERM; the ring buffer poll loop reads it between iterations.
static STOP: AtomicBool = AtomicBool::new(false);

/// A signal handler may only touch async-signal-safe state. An atomic store is
/// the entirety of what is safe here -- the previous version locked a Mutex and
/// dropped a Box from signal context, which is undefined behavior and aborted
/// the process on a second ^C during libbpf teardown.
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // SAFETY: on_signal only performs an atomic store, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        // A daemon behind a pipe gets SIGHUP when the reader closes; handle it
        // so shutdown still runs the summary and clean teardown.
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
    }
}

/// Render a capability mask, naming the interesting bits and counting the rest.
fn format_caps(mask: u64) -> String {
    let named = kernelsentinel::event::cap_names(mask);
    let rest = mask.count_ones() as usize - named.len();
    match (named.is_empty(), rest) {
        (true, n) => format!("{n} unnamed"),
        (false, 0) => named.join(","),
        (false, n) => format!("{},+{n}", named.join(",")),
    }
}
