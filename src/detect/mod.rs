//! The detection engine. It receives each event *after* the graph has been
//! updated, runs the built-in detectors, stores the resulting signals per
//! process, and re-scores the affected lineage. When a lineage's risk crosses
//! into a higher severity band, it emits one incident -- not one alert per
//! event, which is the whole point of the project.

mod alert;
mod detectors;
mod score;
mod signal;

use std::collections::HashMap;

use crate::decoded::Event;
use crate::graph::{ProcKey, ProcessGraph};

pub use alert::render;
pub use score::{Context, Score, Severity};
pub use signal::Signal;

/// One correlated detection: a lineage, its signals, and its score.
pub struct Incident {
    /// The most-recently-active process in the lineage (the alert's subject).
    pub subject: ProcKey,
    pub signals: Vec<Signal>,
    pub score: Score,
    pub attack: Vec<String>,
}

pub struct Engine {
    /// Signals indexed by the process they fired on.
    signals: HashMap<ProcKey, Vec<Signal>>,
    /// Highest severity already reported for a lineage, keyed by its root, so a
    /// steady stream of events does not re-alert until things actually escalate.
    reported: HashMap<ProcKey, Severity>,
    min_severity: Severity,
}

impl Engine {
    pub fn new(min_severity: Severity) -> Self {
        Self {
            signals: HashMap::new(),
            reported: HashMap::new(),
            min_severity,
        }
    }

    /// Feed one event. Returns an incident if this event pushed a lineage into a
    /// new, higher severity band worth reporting.
    pub fn on_event(&mut self, ev: &Event, graph: &ProcessGraph) -> Option<Incident> {
        let new_signals = detectors::detect(ev, graph);
        if new_signals.is_empty() {
            return None;
        }
        let subject = new_signals[0].key;
        let bucket = self.signals.entry(subject).or_default();
        for sig in new_signals {
            // One signal of each kind per process. sudo alone emits ~16 credential
            // events as it brackets its privileges (euid 1 <-> 0); without this,
            // the same logical escalation stacks into a false critical. This is
            // the "net transition per process" collapse: keep the highest-scored
            // instance of each signal id, never sum duplicates.
            match bucket.iter_mut().find(|s| s.id == sig.id) {
                Some(existing) if existing.score >= sig.score => {}
                Some(existing) => *existing = sig,
                None => bucket.push(sig),
            }
        }

        self.evaluate(subject, graph)
    }

    /// Gather every signal in the subject's lineage (itself + ancestors +
    /// descendants of the chain we can see) and score them together.
    fn evaluate(&mut self, subject: ProcKey, graph: &ProcessGraph) -> Option<Incident> {
        // The lineage: ancestors of the subject, plus the subject. Signals on a
        // parent (e.g. the shell that escalated) belong with signals on a child
        // (e.g. the chmod that created the SUID file).
        let lineage: Vec<ProcKey> = graph.ancestry(&subject).iter().map(|n| n.key).collect();
        let lineage = if lineage.is_empty() {
            vec![subject]
        } else {
            lineage
        };

        let mut signals: Vec<Signal> = Vec::new();
        for key in &lineage {
            if let Some(s) = self.signals.get(key) {
                signals.extend(s.iter().cloned());
            }
        }
        if signals.is_empty() {
            return None;
        }

        let ctx = self.context(&lineage, graph);
        let score = score::score(&signals, ctx);

        if score.severity < self.min_severity {
            return None;
        }

        // Deduplicate by lineage root: report only when we cross into a band
        // higher than anything already reported for this chain.
        let root = *lineage.last().unwrap();
        let prev = self.reported.get(&root).copied();
        if prev.is_some_and(|p| score.severity <= p) {
            return None;
        }
        self.reported.insert(root, score.severity);

        let mut attack: Vec<String> = signals
            .iter()
            .flat_map(|s| s.attack.iter().map(|a| a.to_string()))
            .collect();
        attack.sort();
        attack.dedup();

        // Present the signals oldest-first so the chain reads in causal order.
        signals.sort_by_key(|s| s.ts_ns);

        Some(Incident {
            subject,
            signals,
            score,
            attack,
        })
    }

    fn context(&self, lineage: &[ProcKey], graph: &ProcessGraph) -> Context {
        let in_container = lineage
            .iter()
            .filter_map(|k| graph.get(k))
            .any(|n| n.cgroup_id != 0 && is_container_cgroup(n.cgroup_id));

        // Network-daemon rooting: the oldest ancestor's name matches a known
        // network-facing service. Best-effort for M3; refined with real service
        // detection later.
        let network_rooted = lineage
            .last()
            .and_then(|k| graph.get(k))
            .map(|n| is_network_daemon(&n.comm))
            .unwrap_or(false);

        Context {
            network_rooted,
            in_container,
        }
    }
}

/// Ordering so `Severity` can be compared with `<`, `<=`.
impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}
impl Severity {
    fn rank(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }
}

fn is_network_daemon(comm: &str) -> bool {
    const DAEMONS: &[&str] = &[
        "nginx", "apache2", "httpd", "sshd", "postgres", "mysqld", "redis-server", "node",
    ];
    DAEMONS.iter().any(|d| comm == *d)
}

/// A crude container-cgroup heuristic for M3. cgroup ids for containers are
/// large kernfs ids; the real Docker/containerd resolution arrives in M6.
fn is_container_cgroup(_cgroup_id: u64) -> bool {
    // Deliberately conservative: return false until M6 provides real resolution,
    // so the container multiplier never fires on a false guess.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoded::Event;

    fn ev(json: &str) -> Event {
        serde_json::from_str(json).unwrap()
    }

    /// Drive a sequence of events through a graph + engine and collect every
    /// incident the engine chooses to report.
    fn run(events: &[Event], min: Severity) -> Vec<Incident> {
        let mut g = ProcessGraph::new(10_000, std::time::Duration::from_secs(3600));
        let mut e = Engine::new(min);
        let mut out = Vec::new();
        for event in events {
            g.apply(event);
            if let Some(inc) = e.on_event(event, &g) {
                out.push(inc);
            }
        }
        out
    }

    // A shell forks a process that copies a shell, sets SUID, and escalates to
    // root. This must surface as one CRITICAL incident carrying the whole chain.
    fn suid_chain() -> Vec<Event> {
        vec![
            ev(r#"{"ts_ns":1000000000,"type":3,"tgid":100,"ppid":50,"start_boottime":900000000,"comm":"bash","child_pid":200,"child_start_boottime":1000000000}"#),
            ev(r#"{"ts_ns":1002000000,"type":6,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","filename":"/tmp/.x","file_mode":2541,"old_file_mode":33261}"#),
            ev(r#"{"ts_ns":1003000000,"type":4,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","euid":0,"old_euid":1000,"cap_effective":2199023255551}"#),
        ]
    }

    #[test]
    fn suid_escalation_chain_is_critical() {
        let incidents = run(&suid_chain(), Severity::Low);
        let worst = incidents
            .iter()
            .map(|i| i.score.total)
            .max()
            .expect("chain must produce at least one incident");
        assert!(worst >= 90, "SUID + escalation chain should be critical, got {worst}");
        // The reported incident must carry BOTH signals -- that is the point.
        let critical = incidents.iter().max_by_key(|i| i.score.total).unwrap();
        let ids: Vec<&str> = critical.signals.iter().map(|s| s.id).collect();
        assert!(ids.contains(&"suid_create"));
        assert!(ids.contains(&"privilege_escalation"));
    }

    #[test]
    fn bare_sudo_does_not_alert() {
        // A plain sudo: euid 1000 -> 0 and the full root capability set, with no
        // other suspicious signal. This must NOT reach the Medium alert band, or
        // the tool cries wolf every time someone types their password.
        let sudo = vec![ev(
            r#"{"ts_ns":1000000000,"type":4,"tgid":300,"ppid":50,"start_boottime":900000000,"comm":"sudo","euid":0,"old_euid":1000,"cap_effective":2199023255551}"#,
        )];
        let incidents = run(&sudo, Severity::Medium);
        assert!(
            incidents.is_empty(),
            "bare sudo must not produce a Medium+ alert, got {} incidents at {:?}",
            incidents.len(),
            incidents.first().map(|i| i.score.severity)
        );
    }

    #[test]
    fn single_suid_creation_is_low_not_critical() {
        // A lone SUID creation is noteworthy but not a chain; it should be LOW
        // and suppressed at the daemon's Medium threshold.
        let one = vec![ev(
            r#"{"ts_ns":1000000000,"type":6,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","filename":"/tmp/.x","file_mode":2541,"old_file_mode":33261}"#,
        )];
        assert!(run(&one, Severity::Medium).is_empty());
        let low = run(&one, Severity::Low);
        assert_eq!(low.len(), 1);
        assert_eq!(low[0].score.severity, Severity::Low);
    }

    #[test]
    fn escalation_does_not_re_alert_without_escalating() {
        // Once a lineage is reported at CRITICAL, further events in it must not
        // spam identical alerts.
        let mut events = suid_chain();
        // A second, redundant cred change in the same lineage.
        events.push(ev(r#"{"ts_ns":1005000000,"type":4,"tgid":200,"ppid":100,"start_boottime":1000000000,"comm":"chmod","euid":0,"old_euid":1000,"cap_effective":2199023255551}"#));
        let incidents = run(&events, Severity::Low);
        let criticals = incidents
            .iter()
            .filter(|i| i.score.severity == Severity::Critical)
            .count();
        assert_eq!(criticals, 1, "must not re-alert the same critical lineage");
    }
}
