use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use std::io::Write;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use kernelsentinel::clock::BootClock;
use kernelsentinel::decoded::Event;
use kernelsentinel::detect::{self, Baseline, Engine, IncidentRecord, RuleSet, Severity};
use kernelsentinel::doctor;
use kernelsentinel::event::EventType;
#[cfg(feature = "bpf")]
use kernelsentinel::event::RawEvent;
use kernelsentinel::graph::{ProcKey, ProcessGraph, scan};
#[cfg(feature = "bpf")]
use kernelsentinel::{heartbeat, sensors};

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
    /// Live collection. Requires the eBPF sensors, so it is absent from a
    /// server-only build.
    #[cfg(feature = "bpf")]
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
        /// Apply a learned baseline to downweight known-normal behavior.
        #[arg(long)]
        baseline: Option<String>,
        /// Directory of YAML detection rules to load alongside the built-ins.
        #[arg(long)]
        rules: Option<String>,
        /// Directory of YARA rules (.yar/.yara). Files named by an incident are
        /// scanned and any matches attached to it -- identification on top of
        /// detection, not a replacement for it.
        #[arg(long)]
        yara: Option<String>,
        /// Lowest severity worth reporting: info|low|medium|high|critical.
        /// The default suppresses single low signals until they chain, which is
        /// what keeps a bare `sudo` from crying wolf. Lower it to see every
        /// signal a sensor produces -- what the attack suite asserts against.
        #[arg(long, default_value = "medium")]
        min_severity: String,
        /// Block, rather than only report, a narrow set of container escapes:
        /// off (default) | audit | on. `audit` reports what would be blocked
        /// without blocking anything -- run that first.
        #[arg(long, default_value = "off")]
        enforce: String,
    },
    /// Capture raw events to an NDJSON file (no detection), for later replay.
    #[cfg(feature = "bpf")]
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
        /// Apply a learned baseline to downweight known-normal behavior.
        #[arg(long)]
        baseline: Option<String>,
        /// Directory of YAML detection rules to load alongside the built-ins.
        #[arg(long)]
        rules: Option<String>,
    },
    /// Learn a per-host baseline of normal (signal, exe) pairs from a clean
    /// capture, so routine behavior stops firing alerts.
    Baseline {
        /// Clean capture to learn from.
        #[arg(short, long)]
        capture: String,
        /// Where to write the baseline JSON.
        #[arg(short, long)]
        out: String,
    },
    /// Measure the alert budget of a capture: how many incidents it produces at
    /// each severity floor, and what caused them.
    ///
    /// Record a host doing ordinary work, then every incident this reports is a
    /// false positive -- the capture is the assertion, since nothing here can
    /// label ground truth on its own.
    Budget {
        /// Capture to measure.
        #[arg(short, long)]
        capture: String,
        /// Measure with this baseline applied, and show what it removed.
        #[arg(long)]
        baseline: Option<String>,
        /// Directory of YAML detection rules to include.
        #[arg(long)]
        rules: Option<String>,
        /// The floor the offender breakdown is attributed at -- the one you
        /// would actually alert on.
        #[arg(long, default_value = "medium")]
        min_severity: String,
        /// Emit the measurement as JSON, for tracking it over time.
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
    /// Run the central fleet server: agents ingest here, admins view the
    /// dashboard. Reads KS_ADMIN_PASSWORD and KS_INGEST_KEY from the environment.
    Serve {
        /// Address to bind, host:port. Keep it loopback unless TLS is enabled.
        #[arg(long, default_value = "127.0.0.1:8088")]
        bind: String,
        /// Per-agent keys file (host key per line). Recommended over a shared key.
        #[arg(long)]
        keys: Option<String>,
        /// sqlite database path so incidents survive a restart.
        #[arg(long)]
        journal: Option<String>,
        /// Prune incidents older than N days on startup (0 = keep forever).
        #[arg(long, default_value_t = 0)]
        retain_days: u64,
        /// TLS certificate chain (PEM). Enables HTTPS with --tls-key.
        #[arg(long)]
        tls_cert: Option<String>,
        /// TLS private key (PEM).
        #[arg(long)]
        tls_key: Option<String>,
        /// POST alerts as JSON to this URL (Slack/Mattermost-compatible body).
        #[arg(long)]
        alert_webhook: Option<String>,
        /// Pin the webhook's certificate (PEM) instead of using system roots.
        #[arg(long)]
        alert_webhook_ca: Option<String>,
        /// Also send alerts to the local syslog socket.
        #[arg(long)]
        alert_syslog: bool,
        /// Syslog datagram socket path.
        #[arg(long, default_value = "/dev/log")]
        alert_syslog_socket: String,
        /// Lowest severity worth alerting on: INFO|LOW|MEDIUM|HIGH|CRITICAL.
        #[arg(long, default_value = "HIGH")]
        alert_min_severity: String,
        /// Cap alerts delivered per minute (0 = no cap); the rest are counted
        /// and summarized so a storm cannot drown the channel.
        #[arg(long, default_value_t = 30)]
        alert_max_per_min: u32,
    },
    /// Ship incident NDJSON (from `run --json` / `replay --json` on stdin) to a
    /// central fleet server. Host -> central only; no control channel back.
    Ship {
        /// Server ingest URL, e.g. https://central:8088/api/ingest
        url: String,
        /// This host's label (default: the system hostname).
        #[arg(long)]
        host: Option<String>,
        /// Pinned server certificate (PEM) for https URLs.
        #[arg(long)]
        ca: Option<String>,
    },
    /// Validate and list the YAML detection rules in a directory.
    Rules {
        /// Directory of .yaml rules.
        #[arg(short, long, default_value = "rules")]
        dir: String,
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
        #[cfg(feature = "bpf")]
        Command::Record { out } => record(&out),
        Command::Replay {
            input,
            json,
            baseline,
            rules,
        } => replay(&input, json, baseline, rules),
        Command::Baseline { capture, out } => baseline_build(&capture, &out),
        Command::Budget {
            capture,
            baseline,
            rules,
            min_severity,
            json,
        } => budget_report(&capture, baseline, rules, &min_severity, json),
        Command::Investigate { pid, capture } => investigate(pid, &capture),
        Command::Tree { pid } => tree(pid),
        Command::Serve {
            bind,
            keys,
            journal,
            retain_days,
            tls_cert,
            tls_key,
            alert_webhook,
            alert_webhook_ca,
            alert_syslog,
            alert_syslog_socket,
            alert_min_severity,
            alert_max_per_min,
        } => serve_cmd(
            &bind,
            keys,
            journal,
            retain_days,
            tls_cert,
            tls_key,
            alert_webhook,
            alert_webhook_ca,
            alert_syslog,
            alert_syslog_socket,
            alert_min_severity,
            alert_max_per_min,
        ),
        Command::Ship { url, host, ca } => ship_cmd(&url, host, ca),
        Command::Rules { dir } => rules_cmd(&dir),
        #[cfg(feature = "bpf")]
        Command::Run {
            max_processes,
            retain,
            json,
            baseline,
            rules,
            yara,
            enforce,
            min_severity,
        } => run(
            max_processes,
            retain,
            json,
            baseline,
            rules,
            yara,
            &enforce,
            &min_severity,
        ),
    }
}

/// Capture every event as one JSON object per line. This is the raw feed with
/// no detection, so a scenario can be recorded once (as root, briefly) and then
/// replayed unprivileged and deterministically as often as needed.
#[cfg(feature = "bpf")]
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
    status(&format!(
        "kernelsentinel: recording to {out} (ctrl-c to stop)"
    ));

    let trusted = kernelsentinel::fileid::TrustedBinaries::resolve_host();
    status(&format!("kernelsentinel: {}", trusted.summary()));

    let mut count = 0u64;
    let stats = sensors::run(
        &STOP,
        Duration::ZERO,
        // Capturing for later replay never enforces.
        sensors::Enforce::Off,
        0,
        |raw: RawEvent| {
            if raw.tgid == self_pid {
                return;
            }
            let mut ev = Event::from(&raw);
            // Resolved on the recording host and written into the capture: a
            // replay elsewhere must reproduce what this host decided, not
            // re-derive it from the replaying machine's own /usr/bin.
            ev.resolve_trust(&trusted);
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
        },
        // `record` writes a capture for offline replay; liveness is not its job.
        |_| {},
    )?;
    let _ = sink.flush();
    status(&format!(
        "kernelsentinel: recorded {count} events ({} emitted, {} drops)",
        stats.emitted, stats.drops
    ));
    Ok(())
}

/// Replay a capture through the same graph and display the live path uses. No
/// BPF, no root: this is where detection logic is developed and regression-tested.
fn replay(input: &str, json: bool, baseline: Option<String>, rules: Option<String>) -> Result<()> {
    use std::io::BufRead;

    let reader: Box<dyn BufRead> = if input == "-" {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(input)?))
    };

    // A capture's boot-clock timestamps cannot be mapped to a correct wall-clock
    // time here (the original offset was not recorded), so render them as
    // time-since-boot rather than fabricate a local wall-clock reading.
    let mut graph = ProcessGraph::new(usize::MAX, Duration::from_secs(u64::MAX / 2));
    let mut engine = Engine::new(Severity::Low);
    if let Some(path) = &baseline {
        let b = Baseline::load(path).with_context(|| format!("loading baseline {path}"))?;
        status(&format!("kernelsentinel: baseline: {}", b.summary()));
        engine = engine.with_baseline(b);
    }
    if let Some(dir) = &rules {
        let loaded = detect::load_rules(dir).map_err(anyhow::Error::msg)?;
        engine = engine.with_rules(RuleSet::new(loaded));
    }
    let clock = BootClock::boot_relative();

    if !json {
        emit(&format!(
            "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
            "TIME(boot)", "PID", "PPID", "UID", "COMM", "EVENT"
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
                        emit(&IncidentRecord::from_incident(&inc, &graph, None).to_ndjson());
                    } else {
                        emit(&detect::render(&inc, &graph, &clock));
                    }
                }
                if ev.ts_ns.saturating_sub(last_reap) > 10_000_000_000 {
                    graph.reap(ev.ts_ns);
                    engine.reap(&graph);
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

/// Run the central fleet server.
#[allow(clippy::too_many_arguments)]
fn serve_cmd(
    bind: &str,
    keys: Option<String>,
    journal: Option<String>,
    retain_days: u64,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    alert_webhook: Option<String>,
    alert_webhook_ca: Option<String>,
    alert_syslog: bool,
    alert_syslog_socket: String,
    alert_min_severity: String,
    alert_max_per_min: u32,
) -> Result<()> {
    use kernelsentinel::notify;
    use kernelsentinel::server::{AgentKeys, Config, Tls, serve};

    // Reject a bad severity at startup rather than silently alerting on
    // everything (or nothing) once an incident finally arrives.
    let alert_min_severity = notify::parse_min_severity(&alert_min_severity).ok_or_else(|| {
        anyhow::anyhow!("--alert-min-severity must be INFO, LOW, MEDIUM, HIGH, or CRITICAL")
    })?;

    let mut alerts = Vec::new();
    if let Some(url) = alert_webhook {
        let pinned = match &alert_webhook_ca {
            Some(p) => Some(kernelsentinel::http::load_pinned_cert(p)?),
            None => None,
        };
        // Fail fast on a malformed URL; discovering it during an incident is
        // the worst possible time.
        kernelsentinel::http::split_url(&url)
            .map_err(|e| anyhow::anyhow!("--alert-webhook {url}: {e}"))?;
        alerts.push(notify::Sink::Webhook { url, pinned });
    } else if alert_webhook_ca.is_some() {
        anyhow::bail!("--alert-webhook-ca has no effect without --alert-webhook");
    }
    if alert_syslog {
        alerts.push(notify::Sink::Syslog {
            socket: alert_syslog_socket,
        });
    }
    let admin_password = std::env::var("KS_ADMIN_PASSWORD").unwrap_or_default();
    let ingest_key = std::env::var("KS_INGEST_KEY").unwrap_or_default();
    let agent_keys = match keys {
        Some(path) => Some(AgentKeys::load(&path).map_err(anyhow::Error::msg)?),
        None => None,
    };
    let tls = match (tls_cert, tls_key) {
        (Some(c), Some(k)) => Some(Tls { cert: c, key: k }),
        (None, None) => None,
        _ => anyhow::bail!("--tls-cert and --tls-key must be given together"),
    };
    serve(Config {
        addr: bind.to_string(),
        admin_password,
        ingest_key,
        agent_keys,
        alerts,
        alert_min_severity,
        alert_max_per_min,
        journal,
        retain_days,
        tls,
    })
}

/// Ship incident NDJSON from stdin to a central server.
fn ship_cmd(url: &str, host: Option<String>, ca: Option<String>) -> Result<()> {
    use kernelsentinel::server::{hostname, ship};
    let key = std::env::var("KS_INGEST_KEY")
        .map_err(|_| anyhow::anyhow!("set KS_INGEST_KEY to this agent's ingest key"))?;
    let host = host.unwrap_or_else(hostname);
    let stdin = std::io::stdin();
    ship(url, &key, &host, ca.as_deref(), stdin.lock())
}

/// Validate and list the rules in a directory.
fn rules_cmd(dir: &str) -> Result<()> {
    let rules = detect::load_rules(dir).map_err(anyhow::Error::msg)?;
    status(&format!("{} rule(s) in {dir}, all valid:\n", rules.len()));
    for r in &rules {
        let kind = if r.is_sequence() {
            format!("sequence[{}]", r.sequence.len())
        } else {
            "match".to_string()
        };
        emit(&format!(
            "  {:<10} {:<24} score {:<3} {:<10} [{}]",
            if r.id.is_empty() { "-" } else { &r.id },
            r.name,
            r.score,
            kind,
            r.attack.join(", ")
        ));
    }
    Ok(())
}

/// Learn a baseline from a clean capture: replay it, run the detectors on every
/// event, and record each (signal, exe) pair as known-normal. Applying this
/// baseline later downweights those pairs so routine behavior stops alerting.
fn baseline_build(capture: &str, out: &str) -> Result<()> {
    let text = std::fs::read_to_string(capture)?;
    let mut graph = ProcessGraph::new(usize::MAX, Duration::from_secs(u64::MAX / 2));
    let mut baseline = Baseline::new();
    let mut n = 0u64;

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        graph.apply(&ev);
        // Every event widens the learning window, not only the ones that signal:
        // the window is how long the host was watched, and it is what tells a
        // pair seen once in a day from a pair seen once in a second.
        baseline.note_event(ev.ts_ns);
        for sig in detect::signals_for_event(&ev, &graph) {
            let exe = graph
                .get(&sig.key)
                .map(|node| node.exe.clone())
                .unwrap_or_default();
            baseline.observe(sig.id, &exe, sig.ts_ns);
        }
        n += 1;
    }
    baseline.events_observed = n;
    let (total, strong) = (baseline.len(), baseline.strong());
    baseline.save(out)?;
    status(&format!(
        "kernelsentinel: learned {total} patterns from {n} events -> {out}"
    ));
    status(&format!("kernelsentinel: {}", baseline.summary()));

    // A capture too short or too thin to evidence anything still produces a
    // file, and the file still loads. Without this the operator finds out from
    // an alert volume that never dropped, months later.
    if strong == 0 && total > 0 {
        status(
            "kernelsentinel: no pattern is well evidenced -- every entry was seen too few times \
             or within too short a window to suppress much. Record a clean capture spanning \
             hours of the host's normal cycle and learn from that.",
        );
    }
    Ok(())
}

/// Measure how much noise a capture produces. See `kernelsentinel::budget`.
fn budget_report(
    capture: &str,
    baseline: Option<String>,
    rules: Option<String>,
    min_severity: &str,
    json: bool,
) -> Result<()> {
    let floor = parse_severity(min_severity)?;
    let text =
        std::fs::read_to_string(capture).with_context(|| format!("reading capture {capture}"))?;
    let b = kernelsentinel::budget::measure(&text, baseline.as_deref(), rules.as_deref(), floor);
    if json {
        emit(&serde_json::to_string(&b)?);
    } else {
        emit(&b.render(floor));
    }
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
    let clock = BootClock::boot_relative();

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
        if !node.container.is_empty() {
            emit(&format!("container  : {}", node.container));
        }
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
            for ev in timeline
                .iter()
                .filter(|e| e.start_boottime == subject.start_boottime)
            {
                emit(&format!(
                    "  {}  {}",
                    clock.format(ev.ts_ns),
                    event_detail(ev)
                ));
            }
        }

        // ATT&CK techniques from the lineage's signals.
        let mut techniques: Vec<&str> = signals
            .iter()
            .flat_map(|s| s.attack.iter().copied())
            .collect();
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
    // `tree` prints structure and runs no detections, so nothing here consults
    // the trusted table.
    let result = scan::bootstrap(&mut graph, &kernelsentinel::fileid::TrustedBinaries::none());

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
    println!("{prefix}{connector}{} ({}){cred}", node.comm, node.key.pid);

    let children = graph.children_of(key);
    let child_prefix = if prefix.is_empty() {
        "  ".to_string()
    } else if last {
        format!("{prefix}   ")
    } else {
        format!("{prefix}│  ")
    };
    for (i, child) in children.iter().enumerate() {
        print_subtree(graph, child, &child_prefix, i + 1 == children.len());
    }
}

#[cfg(feature = "bpf")]
#[allow(clippy::too_many_arguments)]
fn run(
    max_processes: usize,
    retain_secs: u64,
    json: bool,
    baseline: Option<String>,
    rules: Option<String>,
    yara: Option<String>,
    enforce: &str,
    min_severity: &str,
) -> Result<()> {
    let floor = parse_severity(min_severity)?;
    // Parsed before anything attaches: a typo must not silently leave a host
    // unprotected, or silently arm denial.
    let enforce_mode = match enforce.to_ascii_lowercase().as_str() {
        "off" => sensors::Enforce::Off,
        "audit" => sensors::Enforce::Audit,
        "on" => sensors::Enforce::On,
        other => anyhow::bail!("--enforce must be off, audit or on (got {other:?})"),
    };
    let report = doctor::run();
    if report.fatal() {
        report.print();
        anyhow::bail!("preflight checks failed");
    }

    install_signal_handlers();

    let bootclock = BootClock::new();
    let self_pid = std::process::id();

    let mut graph = ProcessGraph::new(max_processes, Duration::from_secs(retain_secs));
    let mut engine = Engine::new(floor);
    if let Some(path) = &baseline {
        let b = Baseline::load(path).with_context(|| format!("loading baseline {path}"))?;
        status(&format!("kernelsentinel: baseline: {}", b.summary()));
        engine = engine.with_baseline(b);
    }
    if let Some(dir) = &rules {
        let loaded = detect::load_rules(dir).map_err(anyhow::Error::msg)?;
        status(&format!(
            "kernelsentinel: loaded {} custom rules from {dir}",
            loaded.len()
        ));
        engine = engine.with_rules(RuleSet::new(loaded));
    }
    let scanner = match &yara {
        Some(dir) => {
            let s = kernelsentinel::yara::Scanner::load(dir)
                .with_context(|| format!("loading YARA rules from {dir}"))?;
            status(&format!(
                "kernelsentinel: loaded YARA rules from {} file(s) in {dir}",
                s.rule_files()
            ));
            Some(s)
        }
        None => None,
    };
    // Resolve the trusted system binaries before the scan, so processes that
    // predate the agent are recognised too. Like the host mount namespace, this
    // is host state read once at startup: consulting the filesystem per event
    // would let a mid-flight package upgrade change a detection's answer.
    let trusted = kernelsentinel::fileid::TrustedBinaries::resolve_host();
    status(&format!("kernelsentinel: {}", trusted.summary()));
    if !trusted.unresolved().is_empty() {
        status(&format!(
            "kernelsentinel: not installed here: {}",
            trusted.unresolved().join(", ")
        ));
    }

    let boot = scan::bootstrap(&mut graph, &trusted);
    // Recorded once here rather than consulted per event, so detection stays
    // deterministic when the same capture is replayed elsewhere.
    let host_ns = scan::host_mnt_ns();
    graph.set_host_mnt_ns(host_ns);
    status(&format!(
        "kernelsentinel: bootstrapped {} processes from /proc (host mnt_ns {})",
        boot.scanned,
        if host_ns == 0 {
            "unknown".to_string()
        } else {
            host_ns.to_string()
        }
    ));

    status("kernelsentinel: sensors attached, streaming events (ctrl-c to stop)\n");
    if !json {
        emit(&format!(
            "{:<12} {:<7} {:<7} {:<6} {:<16} {}",
            "TIME(boot)", "PID", "PPID", "UID", "COMM", "EVENT"
        ));
    }

    let mut last_reap = 0u64;
    let started = std::time::Instant::now();
    // Proves the sensors are still watching, not merely that this process is
    // still running. See src/canary.rs.
    let canary = kernelsentinel::canary::Canary::new();
    let stats = sensors::run(
        &STOP,
        Duration::from_secs(heartbeat::INTERVAL_SECS),
        enforce_mode,
        host_ns,
        |raw: RawEvent| {
            if raw.tgid == self_pid {
                return;
            }
            // Before any other filtering: the canary is a real exec and must be
            // counted as observed even though it is our own child.
            canary.observe(raw.tgid);
            let mut ev = Event::from(&raw);
            ev.resolve_trust(&trusted);
            graph.apply(&ev);

            // Detection runs after the graph update so lineage queries see this
            // event's process already in place.
            if let Some(inc) = engine.on_event(&ev, &graph) {
                let mut rec = IncidentRecord::from_incident(&inc, &graph, Some(&bootclock));
                // Inline on purpose: a fileless payload lives only as long as
                // its process, so deferring the scan usually means scanning a
                // target that is already gone.
                if let Some(sc) = &scanner {
                    rec.enrich(&inc, sc);
                }
                if json {
                    emit(&rec.to_ndjson());
                } else {
                    emit(&detect::render(&inc, &graph, &bootclock));
                    for r in &rec.yara {
                        if let kernelsentinel::yara::Outcome::Matched { rules } = &r.outcome {
                            emit(&format!("    yara  {}  {}", r.target, rules.join(", ")));
                        }
                    }
                }
            }

            // Reaping on the event stream rather than a timer keeps the daemon
            // single-threaded; an idle host has nothing to reap anyway.
            if ev.ts_ns.saturating_sub(last_reap) > 10_000_000_000 {
                graph.reap(ev.ts_ns);
                engine.reap(&graph);
                last_reap = ev.ts_ns;
            }
            if !json {
                print_event(&bootclock, &ev);
            }
        },
        // Liveness tick. Only the NDJSON stream carries it -- a human watching
        // the terminal can see the daemon is alive; a central server cannot.
        |s: sensors::Stats| {
            let verified = canary.round();
            if verified == Some(false) {
                // Loud on the agent's own stderr as well as in the heartbeat:
                // if the link back to the server has also been cut, this is the
                // only place the operator will see it.
                status(
                    "kernelsentinel: WARNING -- sensors did not observe this agent's own exec; \
                     they may have been detached",
                );
            }
            if json {
                emit(
                    &heartbeat::HeartbeatRecord::new(
                        started.elapsed().as_secs(),
                        s.emitted,
                        s.drops,
                        s.decode_panics,
                        verified,
                        canary.misses(),
                    )
                    .to_ndjson(),
                );
            }
        },
    )?;

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
    if stats.decode_panics > 0 {
        status(&format!(
            "kernelsentinel: WARNING — {} events panicked while decoding (recovered)",
            stats.decode_panics
        ));
    }
    Ok(())
}

/// Write one line to stdout without panicking. `println!` unwraps its write and
/// panics on a broken pipe (reader gone); inside the ring buffer callback that
/// panic unwinds across libbpf's C stack and aborts the process. Here a broken
/// pipe just means the reader left, so signal a clean stop and move on.
fn emit(line: &str) {
    let mut out = std::io::stdout().lock();
    if out
        .write_all(line.as_bytes())
        .and_then(|_| out.write_all(b"\n"))
        .is_err()
    {
        STOP.store(true, Ordering::SeqCst);
    }
}

/// Same, for status/summary messages on stderr. Never panics on a broken pipe.
/// Parse a `--min-severity` value. Shared by `run` and `budget` so a floor
/// means the same thing whether it is deciding what to alert on or what to
/// count.
fn parse_severity(s: &str) -> Result<Severity> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => anyhow::bail!(
            "--min-severity must be info, low, medium, high or critical (got {other:?})"
        ),
    })
}

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
            let mode = if ev.opened_for_write() {
                "write"
            } else {
                "read"
            };
            let label = kernelsentinel::watchlist::label_for(path);
            format!("open[{mode}] {path}  <{label}>")
        }
        EventType::FileMode => {
            let path = &ev.filename;
            let warn = if ev.degraded_path {
                " [path degraded]"
            } else {
                ""
            };
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
            let kind = if ev.ptrace_is_attach() {
                "ATTACH"
            } else {
                "read"
            };
            format!(
                "PTRACE[{kind}] -> pid {} ({})",
                ev.target_pid,
                ev.filename // target comm, stored in the path buffer
            )
        }
        EventType::ExecAnon => {
            let warn = if ev.degraded_path {
                " [path degraded]"
            } else {
                ""
            };
            format!(
                "FILELESS-EXEC from {} {}{}",
                ev.exec_source(),
                ev.filename,
                warn
            )
        }
        EventType::SockConnect => format!("SOCKET-CONNECT {}", ev.filename),
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
#[cfg(feature = "bpf")]
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

#[cfg(feature = "bpf")]
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
