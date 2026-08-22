
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};

use kernelsentinel::clock::BootClock;
use kernelsentinel::decoded::Event;
use kernelsentinel::detect::{self, Engine, IncidentRecord, Severity};
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
        /// Emit incidents as NDJSON (one per line) and suppress the event stream.
        #[arg(long)]
        json: bool,
    },
    /// Capture raw events to an NDJSON file (no detection), for later replay.
    Record {
        /// Output file; use "-" for stdout.
        #[arg(short, long, default_value = "-")]
        out: String,
    },
    /// Replay a recorded NDJSON capture through the graph + display, no root.
    Replay {
        /// Capture file to read; use "-" for stdin.
        input: String,
        /// Emit incidents as NDJSON (one per line) and suppress the event stream.
        #[arg(long)]
        json: bool,
    },
    /// Investigate one process from a capture: lineage, timeline, risk, ATT&CK.
    Investigate {
        /// PID to investigate.
        pid: u32,
        /// Capture file to analyze.
        #[arg(short, long)]
        capture: String,
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
        Command::Record { out } => record(&out),
        Command::Replay { input, json } => replay(&input, json),
        Command::Investigate { pid, capture } => investigate(pid, &capture),
        Command::Tree { pid } => tree(pid),
        Command::Run {
            max_processes,
            retain,
            json,
        } => run(max_processes, retain, json),
    }
}

/// Capture every event as one JSON object per line. This is the raw feed with
/// no detection, so a scenario can be recorded once (as root, briefly) and then
/// replayed unprivileged and deterministically as often as needed.
fn record(out: &str) -> Result<()> {
    let report = doctor::run();
    if report.fatal() {
        report.print();
        anyhow::bail!("preflight checks failed");
    }
    install_signal_handlers();

    let mut sink: Box<dyn Write> = if out == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::io::BufWriter::new(std::fs::File::create(out)?))
    };
    let self_pid = std::process::id();
    status(&format!("kernelsentinel: recording to {out} (ctrl-c to stop)"));

    let mut count = 0u64;
    let stats = sensors::run(&STOP, |raw: RawEvent| {
        if raw.tgid == self_pid {
            return;
        }
        let ev = Event::from(&raw);
        // A serialize/write failure to the capture file is worth stopping for,
        // unlike a broken stdout pipe; surface it and shut down.
        match serde_json::to_string(&ev) {
            Ok(line) => {
                if writeln!(sink, "{line}").is_err() {
                    STOP.store(true, Ordering::SeqCst);
                } else {
                    count += 1;
                }
            }
            Err(e) => status(&format!("kernelsentinel: skipped an event: {e}")),
        }
    })?;
    let _ = sink.flush();
    status(&format!(
        "kernelsentinel: recorded {count} events ({} emitted, {} drops)",
        stats.emitted, stats.drops
    ));
    Ok(())
}

/// Replay a capture through the same graph and display the live path uses. No
/// BPF, no root: this is where detection logic is developed and regression-tested.
fn replay(input: &str, json: bool) -> Result<()> {
    use std::io::BufRead;

    let reader: Box<dyn BufRead> = if input == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(input)?))
    };

    // The capture carries boot-clock timestamps from another moment; render them
    // relative to that capture's own first event rather than this machine's boot.
    let mut graph = ProcessGraph::new(usize::MAX, Duration::from_secs(u64::MAX / 2));
    let mut engine = Engine::new(Severity::Low);
    let clock = BootClock::new();

    if !json {
        emit(&format!(
            "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
            "TIME(UTC)", "PID", "PPID", "UID", "COMM", "EVENT"
        ));
    }

    let mut n = 0u64;
    let mut bad = 0u64;
    let mut last_reap = 0u64;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(&line) {
            Ok(ev) => {
                graph.apply(&ev);
                if let Some(inc) = engine.on_event(&ev, &graph) {
                    if json {
                        emit(&IncidentRecord::from_incident(&inc, &graph).to_ndjson());
                    } else {
                        emit(&detect::render(&inc, &graph, &clock));
                    }
                }
                if ev.ts_ns.saturating_sub(last_reap) > 10_000_000_000 {
                    graph.reap(ev.ts_ns);
                    last_reap = ev.ts_ns;
                }
                if !json {
                    print_event(&clock, &ev);
                }
                n += 1;
            }
            Err(_) => bad += 1,
        }
    }
    let g = graph.stats();
    status(&format!(
        "kernelsentinel: replayed {n} events ({bad} malformed lines skipped), graph {} nodes",
        g.nodes
    ));
    Ok(())
}

/// Investigate one process from a capture. Replays the whole file to rebuild
/// the graph and detection state, then prints everything known about the target
/// pid: identity, lineage, credential history, its event timeline, the signals
/// that fired on its lineage, the risk score, and the ATT&CK techniques. This is
/// the post-incident view -- run it against a capture, no root required.
fn investigate(pid: u32, capture: &str) -> Result<()> {
    use kernelsentinel::detect::attack;

    let text = std::fs::read_to_string(capture)?;
    let mut graph = ProcessGraph::new(usize::MAX, Duration::from_secs(u64::MAX / 2));
    let mut engine = Engine::new(Severity::Info);
    let clock = BootClock::new();

    // Rebuild state, and collect this pid's own events for its timeline.
    let mut timeline: Vec<Event> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        graph.apply(&ev);
        engine.on_event(&ev, &graph);
        if ev.tgid == pid {
            timeline.push(ev);
        }
    }

    // A pid can recur in a long capture; investigate every instance.
    let subjects: Vec<ProcKey> = graph
        .nodes()
        .filter(|n| n.key.pid == pid)
        .map(|n| n.key)
        .collect();

    if subjects.is_empty() {
        status(&format!("no process with pid {pid} found in {capture}"));
        return Ok(());
    }
    if subjects.len() > 1 {
        status(&format!(
            "note: pid {pid} was reused {} times in this capture; showing each",
            subjects.len()
        ));
    }

    for subject in subjects {
        let node = graph.get(&subject).unwrap();
        emit(&format!("\n=== PID {} {} ===", subject.pid, node.comm));
        if !node.exe.is_empty() {
            emit(&format!("executable : {}", node.exe));
        }
        if !node.argv.is_empty() {
            emit(&format!("command    : {}", node.argv.join(" ")));
        }
        emit(&format!("uid        : {} (euid {})", node.uid, node.euid));
        if let Some(exited) = node.exited {
            emit(&format!("exited     : {}", clock.format(exited)));
        }

        // Lineage, root first.
        let chain: Vec<String> = graph
            .ancestry(&subject)
            .iter()
            .rev()
            .map(|n| format!("{}({})", n.comm, n.key.pid))
            .collect();
        if !chain.is_empty() {
            emit(&format!("lineage    : {}", chain.join(" -> ")));
        }

        // Credential transitions.
        if !node.cred_history.is_empty() {
            emit("\ncredential changes:");
            for c in &node.cred_history {
                emit(&format!(
                    "  {}  uid={} euid={} gid={} egid={}",
                    clock.format(c.ts_ns),
                    c.uid,
                    c.euid,
                    c.gid,
                    c.egid
                ));
            }
        }

        // Risk assessment over the lineage.
        let (signals, score) = engine.assess(subject, &graph);
        emit(&format!(
            "\nrisk       : {} {}/100  (base {} + chain {})",
            score.severity.label(),
            score.total,
            score.base,
            score.chain_bonus
        ));
        if !signals.is_empty() {
            emit("signals:");
            for s in &signals {
                emit(&format!(
                    "  {}  {:<22} {}  (+{})",
                    clock.format(s.ts_ns),
                    s.id,
                    s.detail,
                    s.score
                ));
            }
        }

        // This process's own event timeline.
        if !timeline.is_empty() {
            emit("\ntimeline:");
            for ev in timeline.iter().filter(|e| e.start_boottime == subject.start_boottime) {
                emit(&format!("  {}  {}", clock.format(ev.ts_ns), event_detail(ev)));
            }
        }

        // ATT&CK techniques from the lineage's signals.
        let mut techniques: Vec<&str> = signals.iter().flat_map(|s| s.attack.iter().copied()).collect();
        techniques.sort();
        techniques.dedup();
        if !techniques.is_empty() {
            emit("\nMITRE ATT&CK:");
            for t in techniques {
                emit(&format!("  {:<12} {}", t, attack::name(t)));
            }
        }
    }
    Ok(())
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

fn run(max_processes: usize, retain_secs: u64, json: bool) -> Result<()> {
    let report = doctor::run();
    if report.fatal() {
        report.print();
        anyhow::bail!("preflight checks failed");
    }

    install_signal_handlers();

    let bootclock = BootClock::new();
    let self_pid = std::process::id();

    let mut graph = ProcessGraph::new(max_processes, Duration::from_secs(retain_secs));
    let mut engine = Engine::new(Severity::Medium);
    let boot = scan::bootstrap(&mut graph);
    status(&format!(
        "kernelsentinel: bootstrapped {} processes from /proc",
        boot.scanned
    ));

    status("kernelsentinel: sensors attached, streaming events (ctrl-c to stop)\n");
    if !json {
        emit(&format!(
            "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
            "TIME(UTC)", "PID", "PPID", "UID", "COMM", "EVENT"
        ));
    }

    let mut last_reap = 0u64;
    let stats = sensors::run(&STOP, |raw: RawEvent| {
        if raw.tgid == self_pid {
            return;
        }
        let ev = Event::from(&raw);
        graph.apply(&ev);

        // Detection runs after the graph update so lineage queries see this
        // event's process already in place.
        if let Some(inc) = engine.on_event(&ev, &graph) {
            if json {
                emit(&IncidentRecord::from_incident(&inc, &graph).to_ndjson());
            } else {
                emit(&detect::render(&inc, &graph, &bootclock));
            }
        }

        // Reaping on the event stream rather than a timer keeps the daemon
        // single-threaded; an idle host has nothing to reap anyway.
        if ev.ts_ns.saturating_sub(last_reap) > 10_000_000_000 {
            graph.reap(ev.ts_ns);
            last_reap = ev.ts_ns;
        }
        if !json {
            print_event(&bootclock, &ev);
        }
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

fn print_event(clock: &BootClock, ev: &Event) {
    let detail = event_detail(ev);
    emit(&format!(
        "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
        clock.format(ev.ts_ns),
        ev.tgid,
        ev.ppid,
        ev.uid,
        ev.comm,
        detail.trim_end()
    ));
}

/// The human-readable detail string for one event, shared by the live display
/// and the investigate timeline.
fn event_detail(ev: &Event) -> String {
    match ev.event_type() {
        EventType::Exec => {
            let filename = &ev.filename;
            let argv = &ev.argv;
            // argv[0] is conventionally the program name and is already shown
            // as the filename. For shebang scripts the kernel also inserts the
            // script path as argv[1], so drop that repeat too.
            let mut args: &[String] = argv.get(1..).unwrap_or(&[]);
            if args.first().map(String::as_str) == Some(filename.as_str()) {
                args = &args[1..];
            }
            let trunc = if ev.truncated { " …" } else { "" };
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
            let path = &ev.filename;
            let mode = if ev.opened_for_write() { "write" } else { "read" };
            let label = kernelsentinel::watchlist::label_for(path);
            format!("open[{mode}] {path}  <{label}>")
        }
        EventType::FileMode => {
            let path = &ev.filename;
            let warn = if ev.degraded_path { " [path degraded]" } else { "" };
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
            let warn = if ev.degraded_path { " [name only]" } else { "" };
            format!("SETCAP file capabilities set on {}{}", ev.filename, warn)
        }
        EventType::Ptrace => {
            let kind = if ev.ptrace_is_attach() { "ATTACH" } else { "read" };
            format!(
                "PTRACE[{kind}] -> pid {} ({})",
                ev.target_pid,
                ev.filename // target comm, stored in the path buffer
            )
        }
        EventType::ExecAnon => {
            let warn = if ev.degraded_path { " [path degraded]" } else { "" };
            format!(
                "FILELESS-EXEC from {} {}{}",
                ev.exec_source(),
                ev.filename,
                warn
            )
        }
        EventType::Module => {
            let origin = ev.module_origin();
            if origin.is_empty() {
                format!("MODULE-LOAD {}", ev.filename)
            } else {
                format!("MODULE-LOAD {} (via {})", ev.filename, origin)
            }
        }
        EventType::Unknown(t) => format!("unknown type={t}"),
    }
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
