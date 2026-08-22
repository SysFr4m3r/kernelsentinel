
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_handler(move || stop.store(true, Ordering::Relaxed))?;
    }

    let bootclock = BootClock::new();
    let self_pid = std::process::id();

    let mut graph = ProcessGraph::new(max_processes, Duration::from_secs(retain_secs));
    let boot = scan::bootstrap(&mut graph);
    eprintln!(
        "kernelsentinel: bootstrapped {} processes from /proc",
        boot.scanned
    );

    eprintln!("kernelsentinel: sensors attached, streaming events (ctrl-c to stop)\n");
    println!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        "TIME(UTC)", "PID", "PPID", "UID", "COMM", "EVENT"
    );

    let mut last_reap = 0u64;
    let stats = sensors::run(stop, |ev: RawEvent| {
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
    eprintln!(
        "kernelsentinel: graph {} nodes ({} alive), {} reaped, {} evicted, {} scanned nodes adopted",
        g.nodes, g.alive, g.reaped, g.evicted, g.adopted
    );

    eprintln!(
        "\nkernelsentinel: {} events emitted, {} ring buffer drops",
        stats.emitted, stats.drops
    );
    if stats.drops > 0 {
        eprintln!("kernelsentinel: WARNING — dropped events mean blind spots");
    }
    Ok(())
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
        EventType::Unknown(t) => format!("unknown type={t}"),
    };

    println!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        clock.format(ev.ts_ns),
        ev.tgid,
        ev.ppid,
        ev.uid,
        ev.comm(),
        detail.trim_end()
    );
}

/// Minimal SIGINT/SIGTERM handling without pulling in a signal crate.
fn ctrlc_handler<F>(f: F) -> Result<()>
where
    F: FnMut() + Send + 'static,
{
    use std::sync::Mutex;
    static HANDLER: Mutex<Option<Box<dyn FnMut() + Send>>> = Mutex::new(None);

    extern "C" fn on_signal(_: libc::c_int) {
        if let Ok(mut guard) = HANDLER.lock() {
            if let Some(f) = guard.as_mut() {
                f();
            }
        }
    }

    *HANDLER.lock().unwrap() = Some(Box::new(f));
    // SAFETY: on_signal only touches a Mutex-guarded closure that sets an
    // AtomicBool; the poll loop checks the flag between iterations.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
    Ok(())
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
