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
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    // The fixture's boot timestamps are from this machine's uptime range, so the
    // mapped time lands in the past but well after the epoch.
    assert!(ts > 1_600_000_000_000, "ts must be epoch ms, got {ts}");
    assert!(ts <= now_ms, "an event cannot be in the future");
    assert!(
        live["signals"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["ts"].is_u64()),
        "every live signal must carry a wall-clock time"
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
