//! Regression tests driven by REAL captures recorded from the kernel, not
//! hand-written events. These caught two false positives a synthetic fixture
//! could not: sudo's ~16-event privilege bracketing stacking into a false
//! critical, and sudo ptrace-reading its own parent shell. Both are locked in
//! here so they cannot regress.

use std::time::Duration;

use kernelsentinel::decoded::Event;
use kernelsentinel::detect::{Engine, Severity};
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
