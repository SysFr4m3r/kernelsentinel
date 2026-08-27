//! Regression tests driven by REAL captures recorded from the kernel, not
//! hand-written events. These caught two false positives a synthetic fixture
//! could not: sudo's ~16-event privilege bracketing stacking into a false
//! critical, and sudo ptrace-reading its own parent shell. Both are locked in
//! here so they cannot regress.

use std::time::Duration;

use kernelsentinel::decoded::Event;
use kernelsentinel::detect::{
    Baseline, Engine, IncidentRecord, RuleSet, Severity, load_rules, signals_for_event,
};
use kernelsentinel::graph::ProcessGraph;

fn replay(path: &str, min: Severity) -> Vec<(Severity, u32, Vec<String>)> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(min);
    let mut incidents = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            let ids = inc.signals.iter().map(|s| s.id.to_string()).collect();
            incidents.push((inc.score.severity, inc.score.total, ids));
        }
    }
    incidents
}

#[test]
fn host_sudo_suid_chain_is_exactly_one_critical() {
    // A real `sudo sh -c 'cp ...; chmod u+s'` capture: 350 events of genuine
    // sudo noise. The escalation and the SUID creation must correlate into
    // exactly one high-severity incident, and nothing else may cross Medium.
    let incidents = replay("tests/fixtures/host_sudo_suid.ndjson", Severity::Medium);
    assert_eq!(
        incidents.len(),
        1,
        "expected exactly one Medium+ incident, got {incidents:?}"
    );
    let (sev, score, ids) = &incidents[0];
    assert_eq!(*sev, Severity::Critical);
    assert!(*score >= 90);
    assert!(ids.contains(&"suid_create".to_string()));
    assert!(ids.contains(&"privilege_escalation".to_string()));
}

#[test]
fn host_sudo_does_not_stack_into_false_critical() {
    // The bug live validation caught: sudo emits ~16 credential events as it
    // brackets euid 1<->0. Without per-process signal dedup they stacked to a
    // false critical. Assert no incident is built purely from repeated
    // privilege_escalation signals (every Medium+ incident must include a
    // second, different signal kind).
    for (_, _, ids) in replay("tests/fixtures/host_sudo_suid.ndjson", Severity::Medium) {
        let distinct: std::collections::HashSet<_> = ids.iter().collect();
        assert!(
            distinct.len() > 1,
            "an incident fired from a single repeated signal: {ids:?}"
        );
    }
}

#[test]
fn container_suid_as_root_is_low_not_critical() {
    // The container scenario runs entirely as root (runc sets it up), so there
    // is no privilege escalation to chain with. A SUID creation alone must be
    // LOW and suppressed at the daemon's Medium threshold -- never a false
    // critical from a benign container start.
    assert!(
        replay("tests/fixtures/container_suid.ndjson", Severity::Medium).is_empty(),
        "container SUID-as-root must not produce a Medium+ alert"
    );
    let low = replay("tests/fixtures/container_suid.ndjson", Severity::Low);
    assert_eq!(low.len(), 1);
    assert_eq!(low[0].0, Severity::Low);
}

#[test]
fn investigate_data_path_surfaces_the_chain() {
    // The engine.assess() call that `investigate` relies on must, for the SUID
    // creator in the host capture, surface the full lineage assessment:
    // CRITICAL, carrying both the escalation and the SUID-creation signals.
    use kernelsentinel::graph::ProcKey;

    let text = std::fs::read_to_string("tests/fixtures/host_sudo_suid.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Info);
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        e.on_event(&ev, &g);
    }

    // Find the chmod that created the SUID binary.
    let chmod: ProcKey = g
        .nodes()
        .find(|n| n.comm == "chmod")
        .map(|n| n.key)
        .expect("capture must contain the chmod process");

    let (signals, score) = e.assess(chmod, &g);
    assert_eq!(score.severity, Severity::Critical);
    let ids: Vec<&str> = signals.iter().map(|s| s.id).collect();
    assert!(ids.contains(&"suid_create"), "signals: {ids:?}");
    assert!(ids.contains(&"privilege_escalation"), "signals: {ids:?}");
}

#[test]
fn ndjson_incident_record_is_valid_and_complete() {
    // The critical incident from the host capture must serialize to valid JSON
    // carrying the version tag, severity, resolved lineage, and both signals --
    // this is the SIEM-facing contract.
    let text = std::fs::read_to_string("tests/fixtures/host_sudo_suid.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Medium);
    let mut json_lines = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            json_lines.push(IncidentRecord::from_incident(&inc, &g, None).to_ndjson());
        }
    }
    assert_eq!(json_lines.len(), 1, "expected one Medium+ incident");

    // Must parse back as valid JSON with the expected shape.
    let v: serde_json::Value = serde_json::from_str(&json_lines[0]).unwrap();
    assert_eq!(v["schema"], "kernelsentinel.incident/v1");
    assert_eq!(v["severity"], "CRITICAL");
    assert_eq!(v["score"], 100);
    assert_eq!(v["subject"]["comm"], "chmod");
    assert!(v["lineage"].as_array().unwrap().len() >= 4);
    assert_eq!(v["signals"].as_array().unwrap().len(), 2);

    // The responder's first question about a SUID alert is "which command did
    // that?". The record must answer it: the subject's command line, and the
    // command line of the process each signal fired on.
    assert_eq!(v["subject"]["cmdline"], "chmod u+s /tmp/.x");
    let suid = v["signals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "suid_create")
        .expect("suid_create signal");
    assert_eq!(suid["cmdline"], "chmod u+s /tmp/.x");
    let esc = v["signals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "privilege_escalation")
        .expect("privilege_escalation signal");
    assert!(
        esc["cmdline"].as_str().unwrap().starts_with("sudo "),
        "escalation must name the sudo command that caused it, got {:?}",
        esc["cmdline"]
    );

    // lineage_detail carries the same chain with commands attached.
    let ld = v["lineage_detail"].as_array().unwrap();
    assert_eq!(ld.len(), v["lineage"].as_array().unwrap().len());
    assert!(
        ld.iter().any(|n| n["cmdline"]
            .as_str()
            .is_some_and(|c| c.contains("chmod u+s"))),
        "the chain must show the command that created the SUID binary"
    );
    assert!(
        v["attack"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "T1548.001")
    );
}

#[test]
fn module_load_fires_and_captures_the_name() {
    // Real capture of `sudo modprobe dummy`. Verifies the do_init_module sensor
    // end to end: the module_load signal fires and carries the real module name
    // read from the parsed struct module (T1547.006). This was the last sensor
    // that could only be verified against a live module load.
    let text = std::fs::read_to_string("tests/fixtures/module_load.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Info);
    let mut saw_module = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            if let Some(sig) = inc.signals.iter().find(|s| s.id == "module_load") {
                assert!(
                    sig.detail.contains("dummy"),
                    "module name lost: {}",
                    sig.detail
                );
                assert!(sig.attack.contains(&"T1547.006"));
                saw_module = true;
            }
        }
    }
    assert!(
        saw_module,
        "module_load signal never fired on a real module-load capture"
    );
}

// Build a baseline of (signal, exe) pairs from a clean capture.
fn learn(path: &str) -> Baseline {
    let text = std::fs::read_to_string(path).unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut b = Baseline::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        for sig in signals_for_event(&ev, &g) {
            let exe = g.get(&sig.key).map(|n| n.exe.clone()).unwrap_or_default();
            b.observe(sig.id, &exe);
        }
    }
    b
}

fn replay_with(
    path: &str,
    min: Severity,
    baseline: Option<Baseline>,
) -> Vec<(Severity, u32, Vec<String>)> {
    let text = std::fs::read_to_string(path).unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(min);
    if let Some(b) = baseline {
        e = e.with_baseline(b);
    }
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            let ids = inc.signals.iter().map(|s| s.id.to_string()).collect();
            out.push((inc.score.severity, inc.score.total, ids));
        }
    }
    out
}

#[test]
fn baseline_suppresses_routine_sudo_modprobe() {
    // A capture of `sudo modprobe dummy` alerts CRITICAL without a baseline.
    // Learned as normal (its own patterns), it must drop below Medium.
    let baseline = learn("tests/fixtures/module_load.ndjson");
    assert!(baseline.known("privilege_escalation", "/usr/bin/sudo"));

    let without = replay_with("tests/fixtures/module_load.ndjson", Severity::Medium, None);
    assert!(
        !without.is_empty(),
        "routine sudo modprobe is CRITICAL without a baseline"
    );

    let with = replay_with(
        "tests/fixtures/module_load.ndjson",
        Severity::Medium,
        Some(baseline),
    );
    assert!(
        with.is_empty(),
        "baseline should suppress routine sudo modprobe, got {with:?}"
    );
}

#[test]
fn baseline_preserves_novel_attack_signal() {
    // A baseline learned from routine sudo (no SUID creation) must NOT hide a
    // real SUID-creation chain. suid_create is novel, so it keeps full score;
    // the routine escalation is downweighted. The incident survives -- baselining
    // must suppress the routine part without hiding the novel part.
    let baseline = learn("tests/fixtures/module_load.ndjson");
    let incidents = replay_with(
        "tests/fixtures/host_sudo_suid.ndjson",
        Severity::Medium,
        Some(baseline),
    );
    assert_eq!(incidents.len(), 1, "the real SUID chain must still alert");
    let (_, _, ids) = &incidents[0];
    assert!(
        ids.contains(&"suid_create".to_string()),
        "novel signal must survive baselining"
    );
}

#[test]
fn container_context_multiplier_applies() {
    use kernelsentinel::graph::ProcKey;
    // An escalation + SUID chain running inside a container must get the x1.1
    // container context multiplier. Events carry a resolved container label.
    let events = vec![
        ev(
            r#"{"ts_ns":1000000000,"type":3,"tgid":100,"ppid":1,"start_boottime":900000000,"comm":"bash","child_pid":200,"child_start_boottime":1000000000,"container":"docker:abc123def456"}"#,
        ),
        ev(
            r#"{"ts_ns":1002000000,"type":6,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","filename":"/tmp/.x","file_mode":2541,"old_file_mode":33261,"container":"docker:abc123def456"}"#,
        ),
        ev(
            r#"{"ts_ns":1003000000,"type":4,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","euid":0,"old_euid":1000,"cap_effective":2199023255551,"container":"docker:abc123def456"}"#,
        ),
    ];
    let mut g = ProcessGraph::new(1000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Low);
    let mut multiplied = false;
    for event in &events {
        g.apply(event);
        if let Some(inc) = e.on_event(event, &g) {
            if inc.score.context_mult > 1.0 {
                multiplied = true;
            }
        }
    }
    // The node must carry the container label, and the multiplier must have fired.
    let node = g
        .get(&ProcKey {
            pid: 200,
            start_boottime: 1000000000,
        })
        .unwrap();
    assert_eq!(node.container, "docker:abc123def456");
    assert!(
        multiplied,
        "container context multiplier should apply inside a container"
    );
}

fn ev(json: &str) -> Event {
    serde_json::from_str(json).unwrap()
}

#[test]
fn container_events_carry_resolved_id_and_multiplier() {
    // Real capture of the SUID scenario inside an ephemeral --rm Docker
    // container. The cgroup name was captured in-kernel (race-free), so events
    // carry "docker:<id>" even though the container's cgroup is long gone. The
    // container context multiplier must apply.
    let text = std::fs::read_to_string("tests/fixtures/container_suid_tagged.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Low);
    let mut container_incident = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(line).unwrap();
        g.apply(&event);
        if let Some(inc) = e.on_event(&event, &g) {
            if inc.score.context_mult > 1.0 {
                container_incident = true;
            }
        }
    }
    // Some node in the graph must carry a resolved docker container id.
    assert!(
        g.nodes().any(|n| n.container.starts_with("docker:")),
        "no container id was resolved from the capture"
    );
    assert!(
        container_incident,
        "container context multiplier never applied"
    );
}

#[test]
fn host_docker_sock_access_is_low() {
    // Real capture: the host `docker` CLI connecting to /var/run/docker.sock.
    // Routine host tooling -- must be LOW (baseline territory), not an alert.
    let text = std::fs::read_to_string("tests/fixtures/docker_sock.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Info);
    let mut saw_socket = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            if let Some(sig) = inc.signals.iter().find(|s| s.id == "runtime_socket_access") {
                saw_socket = true;
                assert_eq!(
                    sig.score, 25,
                    "host runtime-socket access should be low-scored"
                );
                assert!(sig.attack.contains(&"T1611"));
            }
        }
    }
    assert!(
        saw_socket,
        "the docker.sock connection should produce a signal"
    );
}

#[test]
fn containerized_docker_sock_access_is_high() {
    // The escape case: a *containerized* process reaching the host runtime
    // socket. Same event, but with a container set, it scores far higher --
    // this is the container-escape primitive (T1611).
    let mut g = ProcessGraph::new(1000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Info);
    // fork so the process exists in a container, then connect to docker.sock.
    let fork = serde_json::from_str::<Event>(r#"{"ts_ns":1000000000,"type":3,"tgid":1,"ppid":0,"start_boottime":0,"comm":"sh","child_pid":200,"child_start_boottime":1000000000,"container":"docker:abc123"}"#).unwrap();
    let sock = serde_json::from_str::<Event>(r#"{"ts_ns":1001000000,"type":11,"tgid":200,"ppid":1,"start_boottime":1000000000,"comm":"sh","filename":"/var/run/docker.sock","container":"docker:abc123"}"#).unwrap();
    g.apply(&fork);
    e.on_event(&fork, &g);
    g.apply(&sock);
    let inc = e
        .on_event(&sock, &g)
        .expect("containerized docker.sock access must alert");
    let sig = inc
        .signals
        .iter()
        .find(|s| s.id == "runtime_socket_access")
        .unwrap();
    assert_eq!(
        sig.score, 60,
        "containerized runtime-socket access is the escape primitive"
    );
}

#[test]
fn engine_reap_bounds_state_with_the_graph() {
    // The engine's signal/report maps must not outgrow the graph. After a
    // process is reaped from the graph, engine.reap must drop its state too,
    // or a long-running daemon leaks memory per process ever seen.
    use kernelsentinel::graph::ProcKey;
    let mut g = ProcessGraph::new(1000, Duration::from_secs(5));
    let mut e = Engine::new(Severity::Low);

    // A process is forked (so it exists in the graph), fires a signal, then
    // exits and ages past retention.
    let fork = serde_json::from_str::<Event>(r#"{"ts_ns":999000000,"type":3,"tgid":1,"ppid":0,"start_boottime":0,"comm":"bash","child_pid":200,"child_start_boottime":1000000000}"#).unwrap();
    let suid = serde_json::from_str::<Event>(r#"{"ts_ns":1000000000,"type":6,"tgid":200,"ppid":1,"start_boottime":1000000000,"comm":"chmod","filename":"/tmp/.x","file_mode":2541,"old_file_mode":33261}"#).unwrap();
    let exit = serde_json::from_str::<Event>(
        r#"{"ts_ns":1001000000,"type":2,"tgid":200,"ppid":1,"start_boottime":1000000000}"#,
    )
    .unwrap();
    g.apply(&fork);
    g.apply(&suid);
    e.on_event(&suid, &g);
    g.apply(&exit);

    assert!(
        !e.assess(
            ProcKey {
                pid: 200,
                start_boottime: 1000000000
            },
            &g
        )
        .0
        .is_empty()
    );

    // Reap well past the 5s retention window, then reap the engine.
    g.reap(10_000_000_000);
    e.reap(&g);

    // The reaped process's signals are gone from engine state.
    let (signals, _) = e.assess(
        ProcKey {
            pid: 200,
            start_boottime: 1000000000,
        },
        &g,
    );
    assert!(
        signals.is_empty(),
        "engine retained signals for a reaped process"
    );
}

#[test]
fn yaml_dsl_rule_detects_the_escalation_chain() {
    // The shipped YAML rule (rules/escalate_then_suid.yaml) -- a sequence rule
    // with NO Rust behind it -- must fire on the real host capture, proving a
    // detection can be added declaratively and flow through the same engine.
    let rules = load_rules("rules").expect("rules/ must load and validate");
    assert!(!rules.is_empty());

    let text = std::fs::read_to_string("tests/fixtures/host_sudo_suid.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Low).with_rules(RuleSet::new(rules));

    let mut saw_dsl = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            if inc.signals.iter().any(|sig| sig.id == "KS-DSL-0001") {
                saw_dsl = true;
                assert!(inc.attack.iter().any(|a| a == "T1548.001"));
            }
        }
    }
    assert!(
        saw_dsl,
        "the YAML sequence rule never fired on the real chain"
    );
}

/// The live path must stamp incidents with wall-clock time, and the replay path
/// must not: a capture never recorded the boot->wall offset, so any wall time
/// derived from it on another machine (or after a reboot) would be fiction.
/// In-incident offsets come from the kernel boot clock and stay exact in both.
#[test]
fn wall_clock_is_present_live_and_absent_on_replay() {
    use kernelsentinel::clock::BootClock;

    let text = std::fs::read_to_string("tests/fixtures/host_sudo_suid.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Medium);
    let mut incidents = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            incidents.push(inc);
        }
    }
    let inc = incidents.last().expect("the critical incident");

    // Replay: no clock, so no invented timestamps.
    let replayed: serde_json::Value =
        serde_json::from_str(&IncidentRecord::from_incident(inc, &g, None).to_ndjson()).unwrap();
    assert!(
        replayed.get("ts").is_none(),
        "replay must not invent a wall-clock time"
    );
    assert!(
        replayed["signals"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.get("ts").is_none()),
        "replayed signals must not carry wall-clock times"
    );

    // Live: a real clock produces a plausible current epoch-millisecond stamp.
    let clock = BootClock::new();
    let live: serde_json::Value =
        serde_json::from_str(&IncidentRecord::from_incident(inc, &g, Some(&clock)).to_ndjson())
            .unwrap();
    let ts = live["ts"].as_u64().expect("live records must carry `ts`");
    assert!(ts > 1_600_000_000_000, "ts must be epoch ms, got {ts}");
    // Deliberately NOT asserting the mapped time is in the past. These are a
    // *capture's* boot timestamps run through *this* machine's boot epoch, which
    // clock.rs says outright is meaningless -- and it shows: on a host whose
    // uptime is shorter than the capture's span (any fresh CI runner) the result
    // lands in the future. Asserting otherwise encoded an assumption the design
    // rejects, and passed only because the dev machine had days of uptime.
    // What the live path actually promises is tested below, on the clock itself.
    assert!(
        live["signals"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["ts"].is_u64()),
        "every live signal must carry a wall-clock time"
    );

    // The conversion itself is the real contract: a fixed offset from the boot
    // epoch, so differences survive exactly and "now" maps to now.
    let a = clock.to_epoch_ms(1_000_000_000);
    let b = clock.to_epoch_ms(3_500_000_000);
    assert_eq!(
        b - a,
        2_500,
        "2.5s apart in boot ns must be 2500ms apart in wall ms"
    );
    let uptime_ns = std::time::Duration::from_secs_f64(
        std::fs::read_to_string("/proc/uptime")
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<f64>()
            .unwrap(),
    )
    .as_nanos() as u64;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mapped_now = clock.to_epoch_ms(uptime_ns);
    assert!(
        mapped_now.abs_diff(now_ms) < 5_000,
        "the current uptime must map back to roughly now: {mapped_now} vs {now_ms}"
    );

    // Offsets inside the incident are exact regardless of clock availability.
    let sigs = replayed["signals"].as_array().unwrap();
    let lo = sigs
        .iter()
        .map(|s| s["ts_ns"].as_u64().unwrap())
        .min()
        .unwrap();
    let hi = sigs
        .iter()
        .map(|s| s["ts_ns"].as_u64().unwrap())
        .max()
        .unwrap();
    assert!(hi > lo, "the chain must have measurable ordering");
}

/// Secrets on a command line must not survive into the shipped record. argv now
/// reaches the panel, the sqlite journal, webhook bodies posted to a third
/// party, and syslog -- so a leak here is replicated into all four.
#[test]
fn command_line_secrets_never_reach_the_shipped_record() {
    // An exec event carrying a password inline, as the kernel would deliver it.
    let raw = serde_json::json!({
        "ts_ns": 1_000, "type": 1, "tgid": 4242, "ppid": 1, "start_boottime": 900,
        "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 1,
        "comm": "mysql", "filename": "/usr/bin/mysql",
        "argv": ["/usr/bin/mysql", "-uroot", "-phunter2", "--token", "abc123"]
    });
    let ev: Event = serde_json::from_str(&raw.to_string()).unwrap();
    let joined = ev.argv.join(" ");
    assert!(
        !joined.contains("hunter2") && !joined.contains("abc123"),
        "secrets survived decoding: {joined}"
    );
    assert!(
        joined.contains("-uroot"),
        "non-secret arguments must survive"
    );
    assert!(joined.contains("-p<redacted>"), "got: {joined}");
    // ...and through the graph into the record the agent ships.
    let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
    g.apply(&ev);
    let node = g
        .get(&kernelsentinel::graph::ProcKey {
            pid: 4242,
            start_boottime: 900,
        })
        .expect("process in graph");
    assert!(
        !node.argv.join(" ").contains("hunter2"),
        "secret reached the process graph"
    );
}

/// Content scanning must be driven by what a signal actually named. The
/// critical fixture chain creates /tmp/.x, so that file -- and only that file --
/// is what the incident should offer for inspection.
#[test]
fn yara_enrichment_scans_the_files_the_signals_named() {
    use kernelsentinel::yara::{Outcome, Scanner};

    // A scratch rules directory; the project carries no tempfile dependency.
    let dir = std::env::temp_dir().join(format!(
        "ks-enrich-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("r.yar"),
        r#"rule ks_enrich_probe { strings: $a = "ZZ_NEVER_PRESENT_ZZ" condition: $a }"#,
    )
    .unwrap();
    let scanner = Scanner::load(dir.to_str().unwrap()).unwrap();

    let text = std::fs::read_to_string("tests/fixtures/host_sudo_suid.ndjson").unwrap();
    let mut g = ProcessGraph::new(100_000, Duration::from_secs(3600));
    let mut e = Engine::new(Severity::Medium);
    let mut last = None;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let ev: Event = serde_json::from_str(line).unwrap();
        g.apply(&ev);
        if let Some(inc) = e.on_event(&ev, &g) {
            last = Some(inc);
        }
    }
    let inc = last.expect("the critical incident");

    let mut rec = IncidentRecord::from_incident(&inc, &g, None);
    assert!(rec.yara.is_empty(), "no scanning until enrich runs");
    rec.enrich(&inc, &scanner);

    assert!(
        !rec.yara.is_empty(),
        "the chain named a file worth scanning"
    );
    let suid = rec
        .yara
        .iter()
        .find(|r| r.signal == "suid_create")
        .expect("suid_create names its file");
    assert_eq!(
        suid.target, "/tmp/.x",
        "must scan the file that gained SUID"
    );

    // The fixture deletes /tmp/.x, so the honest outcome is a lost race -- and
    // it must be reported as such, never as "clean". Confusing "gone before we
    // looked" with "inspected and safe" is the dangerous failure here.
    assert!(
        matches!(suid.outcome, Outcome::Raced { .. }),
        "a target that no longer exists must report Raced, got {:?}",
        suid.outcome
    );

    // One scan per file, however many signals point at it.
    let mut targets: Vec<&str> = rec.yara.iter().map(|r| r.target.as_str()).collect();
    let before = targets.len();
    targets.sort_unstable();
    targets.dedup();
    assert_eq!(before, targets.len(), "a file must not be scanned twice");

    // Enrichment is identification, not scoring.
    let json: serde_json::Value = serde_json::from_str(&rec.to_ndjson()).unwrap();
    assert_eq!(json["score"], 100, "a scan must not move the score");
    assert!(json["yara"].is_array());

    std::fs::remove_dir_all(&dir).ok();
}

/// Reading the credential store is the theft shape; writing it is the tampering
/// shape. Both are worth seeing, but a read fires during every authentication on
/// the host, so it must not be able to alert on its own.
#[test]
fn credential_reads_are_detected_suppressed_and_scored_below_the_floor() {
    fn open_event(pid: u32, comm: &str, path: &str, write: bool) -> Event {
        let v = serde_json::json!({
            "ts_ns": 2_000u64 + pid as u64, "type": 5, "tgid": pid, "ppid": 1,
            "start_boottime": 1_000u64 + pid as u64,
            "uid": 1000, "gid": 1000, "euid": 1000, "egid": 1000, "cgroup_id": 1,
            "comm": comm, "filename": path,
            "file_mode": if write { 0x2 } else { 0x1 },
            "watch_id": 1
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }
    fn exec_event(pid: u32, comm: &str) -> Event {
        let v = serde_json::json!({
            "ts_ns": 1_000u64 + pid as u64, "type": 1, "tgid": pid, "ppid": 1,
            "start_boottime": 1_000u64 + pid as u64,
            "uid": 1000, "gid": 1000, "euid": 1000, "egid": 1000, "cgroup_id": 1,
            "comm": comm, "filename": format!("/usr/bin/{comm}"), "argv": [comm]
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }

    let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
    let signals_for = |g: &mut ProcessGraph, pid: u32, comm: &str, path: &str, write: bool| {
        let e = exec_event(pid, comm);
        g.apply(&e);
        let o = open_event(pid, comm, path, write);
        g.apply(&o);
        kernelsentinel::detect::signals_for_event(&o, g)
    };

    // An unexpected reader of /etc/shadow is a signal...
    let sigs = signals_for(&mut g, 4001, "curl", "/etc/shadow", false);
    assert_eq!(sigs.len(), 1, "an unexpected read must be detected");
    assert_eq!(sigs[0].id, "credential_store_read");
    assert!(
        sigs[0].score < 50,
        "a credential read must sit below the alerting floor, got {}",
        sigs[0].score
    );

    // ...but the programs whose job is authentication are not. Without this the
    // signal would fire on every sudo, ssh login and getent on the box.
    for reader in ["unix_chkpwd", "sshd", "sudo", "su"] {
        let sigs = signals_for(
            &mut g,
            4100 + reader.len() as u32,
            reader,
            "/etc/shadow",
            false,
        );
        assert!(
            sigs.is_empty(),
            "{reader} reading shadow must be suppressed"
        );
    }

    // An SSH private key read scores higher: sshd loads host keys once at
    // startup, so anything else reading them is far more diagnostic.
    let sigs = signals_for(&mut g, 4200, "cat", "/etc/ssh/ssh_host_rsa_key", false);
    assert_eq!(sigs[0].id, "ssh_private_key_read");
    assert!(sigs[0].score > 30);
    assert_eq!(
        sigs[0].target.as_deref(),
        Some("/etc/ssh/ssh_host_rsa_key"),
        "the key file must be offered for content scanning"
    );

    // A write to the same path is still the tampering signal, not the read one.
    let sigs = signals_for(&mut g, 4300, "curl", "/etc/shadow", true);
    assert_eq!(
        sigs[0].id, "cred_config_write",
        "writes keep their own signal"
    );
}

/// The read signal must not alert alone, but must push a chain over the line --
/// that is the entire reason for scoring it low rather than dropping it.
#[test]
fn a_credential_read_alone_is_quiet_but_lifts_a_chain() {
    use kernelsentinel::detect::signals_for_event;

    let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
    let exec = serde_json::json!({
        "ts_ns": 1_000, "type": 1, "tgid": 5001, "ppid": 1, "start_boottime": 900,
        "uid": 1000, "gid": 1000, "euid": 1000, "egid": 1000, "cgroup_id": 1,
        "comm": "curl", "filename": "/usr/bin/curl", "argv": ["curl"]
    });
    let ev: Event = serde_json::from_str(&exec.to_string()).unwrap();
    g.apply(&ev);
    let read = serde_json::json!({
        "ts_ns": 2_000, "type": 5, "tgid": 5001, "ppid": 1, "start_boottime": 900,
        "uid": 1000, "gid": 1000, "euid": 1000, "egid": 1000, "cgroup_id": 1,
        "comm": "curl", "filename": "/etc/shadow", "file_mode": 1, "watch_id": 1
    });
    let ev: Event = serde_json::from_str(&read.to_string()).unwrap();
    g.apply(&ev);
    let sigs = signals_for_event(&ev, &g);
    assert_eq!(sigs.len(), 1);
    assert_eq!(
        kernelsentinel::detect::Severity::from_score(sigs[0].score),
        kernelsentinel::detect::Severity::Low,
        "on its own it must stay below the medium alerting floor"
    );
}

/// A containerised process running in the host's mount namespace is what having
/// escaped looks like from outside. Scoped to the mount namespace deliberately:
/// --net=host and --pid=host are ordinary configuration, and flagging those
/// would bury the signal in normal Kubernetes.
#[test]
fn a_container_in_the_host_mount_namespace_is_an_escape() {
    const HOST_MNT: u32 = 4_026_531_841;

    fn exec(pid: u32, container: &str, mnt_ns: u32) -> Event {
        let v = serde_json::json!({
            "ts_ns": 1_000u64 + pid as u64, "type": 1, "tgid": pid, "ppid": 1,
            "start_boottime": 900u64 + pid as u64,
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 77,
            "comm": "sh", "filename": "/bin/sh", "argv": ["sh"],
            "container": container, "mnt_ns": mnt_ns
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }
    let run = |host: u32, ev: &Event| {
        let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
        g.set_host_mnt_ns(host);
        g.apply(ev);
        kernelsentinel::detect::signals_for_event(ev, &g)
    };
    let ids =
        |sigs: &[kernelsentinel::detect::Signal]| sigs.iter().map(|s| s.id).collect::<Vec<_>>();

    // The escape: cgroup says container, mount namespace says host.
    let sigs = run(HOST_MNT, &exec(9001, "docker:abc123", HOST_MNT));
    assert!(
        ids(&sigs).contains(&"namespace_escape"),
        "a container in the host mount namespace must be flagged, got {:?}",
        ids(&sigs)
    );

    // A container in its own namespace is just a container.
    let sigs = run(HOST_MNT, &exec(9002, "docker:abc123", 4_026_532_500));
    assert!(!ids(&sigs).contains(&"namespace_escape"));

    // A host process in the host namespace is the normal case, not an escape.
    let sigs = run(HOST_MNT, &exec(9003, "", HOST_MNT));
    assert!(!ids(&sigs).contains(&"namespace_escape"));

    // Replay: the host namespace was never recorded, so it must stay quiet
    // rather than guess. Silence is the honest answer here.
    let sigs = run(0, &exec(9004, "docker:abc123", HOST_MNT));
    assert!(
        !ids(&sigs).contains(&"namespace_escape"),
        "without a known host namespace this must not fire"
    );
}

/// core_pattern and friends name a program the kernel runs as root on the host.
/// Writing one from inside a container is an escape, because the payload runs
/// outside the namespace that asked for it.
#[test]
fn kernel_escape_hatch_writes_outrank_ordinary_persistence() {
    fn write_to(pid: u32, path: &str, container: &str) -> Event {
        let v = serde_json::json!({
            "ts_ns": 2_000u64 + pid as u64, "type": 5, "tgid": pid, "ppid": 1,
            "start_boottime": 900u64 + pid as u64,
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 1,
            "comm": "sh", "filename": path, "file_mode": 2, "watch_id": 1,
            "container": container
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }
    let sigs = |ev: &Event| {
        let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
        g.apply(ev);
        kernelsentinel::detect::signals_for_event(ev, &g)
    };

    for path in [
        "/proc/sys/kernel/core_pattern",
        "/proc/sys/kernel/modprobe",
        "/sys/kernel/uevent_helper",
        "/proc/sys/fs/binfmt_misc/register",
    ] {
        let s = sigs(&write_to(8001, path, ""));
        assert_eq!(s[0].id, "kernel_escape_hatch_write", "for {path}");
        assert!(
            s[0].target.as_deref() == Some(path),
            "the file must be scannable"
        );
    }

    // From a container the same write is an escape, and must score higher.
    let host = sigs(&write_to(8002, "/proc/sys/kernel/core_pattern", ""));
    let contained = sigs(&write_to(
        8003,
        "/proc/sys/kernel/core_pattern",
        "docker:abc123",
    ));
    assert!(
        contained[0].score > host[0].score,
        "containerised: {} must exceed host: {}",
        contained[0].score,
        host[0].score
    );
    assert!(contained[0].detail.contains("escape"));

    // An ordinary watched write is untouched by all of this.
    let other = sigs(&write_to(8004, "/etc/cron.d/evil", ""));
    assert_eq!(other[0].id, "persistence_write");
}

/// Enforcement outcome has to lead the detail. An operation the kernel blocked
/// reads very differently from one that succeeded, and a responder who misses
/// that wastes time on an attack that never landed.
#[test]
fn a_blocked_escape_says_so_and_is_still_recorded() {
    fn hatch_write(pid: u32, denied: bool, would_deny: bool) -> Event {
        let v = serde_json::json!({
            "ts_ns": 3_000u64 + pid as u64, "type": 5, "tgid": pid, "ppid": 1,
            "start_boottime": 900u64 + pid as u64,
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 1,
            "comm": "sh", "filename": "/proc/sys/kernel/core_pattern",
            "file_mode": 2, "watch_id": 5, "container": "docker:abc123",
            "denied": denied, "would_deny": would_deny
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }
    let sigs = |ev: &Event| {
        let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
        g.apply(ev);
        kernelsentinel::detect::signals_for_event(ev, &g)
    };

    // Blocked: still a signal, and the detail says it was stopped. A denial
    // that produced no record would be the worst of both worlds.
    let s = sigs(&hatch_write(7001, true, false));
    assert_eq!(s.len(), 1, "a denied operation must still be recorded");
    assert_eq!(s[0].id, "kernel_escape_hatch_write");
    assert!(s[0].detail.starts_with("BLOCKED:"), "got: {}", s[0].detail);

    // Audit: reported as hypothetical, because nothing was actually stopped.
    let s = sigs(&hatch_write(7002, false, true));
    assert!(
        s[0].detail.starts_with("would be blocked:"),
        "got: {}",
        s[0].detail
    );

    // Detect-only: no enforcement language at all.
    let s = sigs(&hatch_write(7003, false, false));
    assert!(!s[0].detail.contains("BLOCKED"));
    assert!(!s[0].detail.contains("would be blocked"));
    assert!(s[0].detail.contains("escape"));

    // The score is the same either way: blocking changes the outcome, not how
    // serious the attempt was.
    let blocked = sigs(&hatch_write(7004, true, false))[0].score;
    let allowed = sigs(&hatch_write(7005, false, false))[0].score;
    assert_eq!(blocked, allowed);
}

/// The regression that synthetic tests could not have caught.
///
/// A container escape bind-mounts the host's /proc somewhere else, so the
/// kernel reports the path as `/hostproc/sys/kernel/core_pattern` and no
/// watched prefix matches. Detection therefore cannot key on the path. This
/// pins that an identity match alone is enough -- the path here is one no
/// watchlist entry would ever match.
#[test]
fn an_escape_hatch_reached_through_a_bind_mount_is_still_caught() {
    fn relocated(denied: bool) -> Event {
        let v = serde_json::json!({
            "ts_ns": 9_000, "type": 5, "tgid": 6001, "ppid": 1, "start_boottime": 900,
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 1,
            "comm": "sh",
            // Deliberately NOT a watched path.
            "filename": "/hostproc/sys/kernel/core_pattern",
            "file_mode": 2, "container": "docker:92c3fb0dff3b",
            "escape_target": true, "denied": denied
        });
        serde_json::from_str(&v.to_string()).unwrap()
    }
    let sigs = |ev: &Event| {
        let mut g = ProcessGraph::new(1_000, Duration::from_secs(3600));
        g.apply(ev);
        kernelsentinel::detect::signals_for_event(ev, &g)
    };

    // Path matching alone would miss this entirely -- confirm it would have.
    let path_only: Event = serde_json::from_str(
        &serde_json::json!({
            "ts_ns": 9_001, "type": 5, "tgid": 6002, "ppid": 1, "start_boottime": 901,
            "uid": 0, "gid": 0, "euid": 0, "egid": 0, "cgroup_id": 1,
            "comm": "sh", "filename": "/hostproc/sys/kernel/core_pattern",
            "file_mode": 2, "container": "docker:92c3fb0dff3b"
        })
        .to_string(),
    )
    .unwrap();
    assert_ne!(
        sigs(&path_only).first().map(|s| s.id),
        Some("kernel_escape_hatch_write"),
        "this path is not watched -- if it matched, the test proves nothing"
    );

    // With the identity flag the same event is caught, escape-scored.
    let s = sigs(&relocated(true));
    assert_eq!(s[0].id, "kernel_escape_hatch_write");
    assert_eq!(s[0].score, 75, "containerised writers get the escape score");
    assert!(s[0].detail.starts_with("BLOCKED:"), "got: {}", s[0].detail);
}
