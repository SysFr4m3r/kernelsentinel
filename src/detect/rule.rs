//! The YAML detection-rule DSL. A rule expresses "this event (or this sequence
//! of events), with these field conditions, in this scope" and produces a
//! signal just like a built-in detector -- so custom rules flow through the same
//! correlation and scoring. Rules are how a detection is added without
//! recompiling.
//!
//! Two rule shapes:
//!   - `match:` a single event with field conditions -> one signal on match.
//!   - `sequence:` an ordered list of event conditions in a scope, within a time
//!     window -> one signal when the whole sequence completes.

use serde::Deserialize;

use crate::decoded::Event;
use crate::event::EventType;

/// Field conditions on one event. All present conditions must hold (AND).
#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Event type name: exec, exit, fork, cred_change, file_open, file_mode,
    /// setcap, ptrace, exec_anon, module, sock_connect.
    pub event: String,
    #[serde(default)]
    pub filename_equals: Option<String>,
    #[serde(default)]
    pub filename_prefix: Option<String>,
    #[serde(default)]
    pub filename_contains: Option<String>,
    #[serde(default)]
    pub comm_equals: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub euid: Option<u32>,
    /// cred_change: effective uid became 0.
    #[serde(default)]
    pub to_root: Option<bool>,
    /// file_mode: a setuid/setgid bit was newly gained.
    #[serde(default)]
    pub gained_suid: Option<bool>,
    /// exec_anon: source is memfd | anon-inode | deleted-file.
    #[serde(default)]
    pub exec_source: Option<String>,
    /// process is / is not inside a container.
    #[serde(default)]
    pub in_container: Option<bool>,
}

impl Condition {
    fn type_matches(&self, ev: &Event) -> bool {
        parse_event_type(&self.event) == Some(ev.event_type())
    }

    /// Does this event satisfy every present condition?
    pub fn matches(&self, ev: &Event) -> bool {
        if !self.type_matches(ev) {
            return false;
        }
        if let Some(v) = &self.filename_equals {
            if &ev.filename != v {
                return false;
            }
        }
        if let Some(v) = &self.filename_prefix {
            if !ev.filename.starts_with(v) {
                return false;
            }
        }
        if let Some(v) = &self.filename_contains {
            if !ev.filename.contains(v) {
                return false;
            }
        }
        if let Some(v) = &self.comm_equals {
            if &ev.comm != v {
                return false;
            }
        }
        if let Some(v) = self.uid {
            if ev.uid != v {
                return false;
            }
        }
        if let Some(v) = self.euid {
            if ev.euid != v {
                return false;
            }
        }
        if let Some(true) = self.to_root {
            if !(ev.old_euid != 0 && ev.euid == 0) {
                return false;
            }
        }
        if let Some(true) = self.gained_suid {
            if ev.gained_bits() == "none" {
                return false;
            }
        }
        if let Some(v) = &self.exec_source {
            if ev.exec_source() != v {
                return false;
            }
        }
        if let Some(want) = self.in_container {
            if ev.container.is_empty() == want {
                return false;
            }
        }
        true
    }
}

/// How a sequence's steps are correlated.
#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// All steps on the same process.
    #[default]
    SameProcess,
    /// Steps on any process in the same ancestor/descendant lineage.
    SameLineage,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub id: String,
    pub score: u32,
    #[serde(default)]
    pub attack: Vec<String>,
    #[serde(default)]
    pub description: String,

    /// Single-event rule.
    #[serde(default)]
    pub r#match: Option<Condition>,

    /// Sequence rule: ordered steps that must all occur in scope within `within`.
    #[serde(default)]
    pub sequence: Vec<Condition>,
    #[serde(default)]
    pub scope: Scope,
    /// Time window for a sequence, e.g. "30s", "500ms". Parsed to nanoseconds.
    #[serde(default)]
    pub within: Option<String>,
}

impl Rule {
    pub fn is_sequence(&self) -> bool {
        !self.sequence.is_empty()
    }

    /// The sequence window in nanoseconds (default 60s if unspecified).
    pub fn within_ns(&self) -> u64 {
        self.within
            .as_deref()
            .and_then(parse_duration_ns)
            .unwrap_or(60_000_000_000)
    }

    /// Structural validation beyond what serde enforces.
    pub fn validate(&self) -> Result<(), String> {
        if self.r#match.is_none() && self.sequence.is_empty() {
            return Err(format!(
                "rule '{}': needs a `match` or a `sequence`",
                self.name
            ));
        }
        if self.r#match.is_some() && !self.sequence.is_empty() {
            return Err(format!(
                "rule '{}': has both `match` and `sequence` (pick one)",
                self.name
            ));
        }
        let all: Vec<&Condition> = self.r#match.iter().chain(self.sequence.iter()).collect();
        for c in all {
            if parse_event_type(&c.event).is_none() {
                return Err(format!(
                    "rule '{}': unknown event type '{}'",
                    self.name, c.event
                ));
            }
        }
        if let Some(w) = &self.within {
            if parse_duration_ns(w).is_none() {
                return Err(format!("rule '{}': bad duration '{}'", self.name, w));
            }
        }
        Ok(())
    }
}

/// Map a DSL event name to an EventType.
fn parse_event_type(name: &str) -> Option<EventType> {
    Some(match name {
        "exec" => EventType::Exec,
        "exit" => EventType::Exit,
        "fork" => EventType::Fork,
        "cred_change" => EventType::CredChange,
        "file_open" => EventType::FileOpen,
        "file_mode" => EventType::FileMode,
        "setcap" => EventType::Setcap,
        "ptrace" => EventType::Ptrace,
        "exec_anon" => EventType::ExecAnon,
        "module" => EventType::Module,
        "sock_connect" => EventType::SockConnect,
        _ => return None,
    })
}

/// Parse "30s", "500ms", "2m" to nanoseconds.
fn parse_duration_ns(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1_000_000u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000_000_000)
    } else {
        let n = s.strip_suffix('m')?;
        (n, 60_000_000_000)
    };
    num.trim().parse::<u64>().ok().map(|v| v * mult)
}

/// Load and validate all rules from a directory of .yaml/.yml files.
pub fn load_dir(dir: &str) -> Result<Vec<Rule>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("reading {dir}: {e}"))?;
    let mut rules = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yaml" || e == "yml");
        if !is_yaml {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let rule: Rule =
            serde_yaml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        rule.validate()?;
        rules.push(rule);
    }
    Ok(rules)
}

// ---------------------------------------------------------------------------
// Rule engine: evaluate loaded rules against the event stream, producing the
// same Signal type the built-in detectors do.

use std::collections::HashMap;

use super::signal::Signal;
use crate::graph::{ProcKey, ProcessGraph};

/// One in-flight sequence match: how far through the steps, and when it started.
struct Partial {
    step: usize,
    first_ts: u64,
    last_ts: u64,
}

pub struct RuleSet {
    rules: Vec<Rule>,
    /// ATT&CK id slices, leaked to 'static so signals can hold them (the
    /// built-in detectors use &'static [&'static str]; rules are loaded once at
    /// startup and live for the process, so leaking is bounded and fine).
    attack: Vec<&'static [&'static str]>,
    /// In-flight sequence state, keyed by (rule index, scope key).
    partials: HashMap<(usize, ProcKey), Partial>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        let attack: Vec<&'static [&'static str]> = rules
            .iter()
            .map(|r| {
                let v: Vec<&'static str> = r
                    .attack
                    .iter()
                    .map(|a| &*Box::leak(a.clone().into_boxed_str()))
                    .collect();
                &*Box::leak(v.into_boxed_slice())
            })
            .collect();
        RuleSet {
            rules,
            attack,
            partials: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The name a rule contributes to signals: its id if set, else its name.
    fn signal_id(&self, idx: usize) -> &'static str {
        let r = &self.rules[idx];
        let s = if r.id.is_empty() { &r.name } else { &r.id };
        Box::leak(s.clone().into_boxed_str())
    }

    fn scope_key(&self, ev: &Event, scope: Scope, graph: &ProcessGraph) -> ProcKey {
        let self_key = ProcKey {
            pid: ev.tgid,
            start_boottime: ev.start_boottime,
        };
        match scope {
            Scope::SameProcess => self_key,
            Scope::SameLineage => graph
                .ancestry(&self_key)
                .last()
                .map(|n| n.key)
                .unwrap_or(self_key),
        }
    }

    /// Evaluate all rules against one event, returning any signals produced.
    pub fn on_event(&mut self, ev: &Event, graph: &ProcessGraph) -> Vec<Signal> {
        let mut out = Vec::new();

        for idx in 0..self.rules.len() {
            let key = ProcKey {
                pid: ev.tgid,
                start_boottime: ev.start_boottime,
            };

            if let Some(cond) = self.rules[idx].r#match.clone() {
                if cond.matches(ev) {
                    out.push(self.make_signal(idx, key, ev.ts_ns));
                }
                continue;
            }

            if self.rules[idx].is_sequence() {
                if let Some(sig) = self.advance_sequence(idx, ev, graph) {
                    out.push(sig);
                }
            }
        }
        out
    }

    fn advance_sequence(&mut self, idx: usize, ev: &Event, graph: &ProcessGraph) -> Option<Signal> {
        let scope = self.rules[idx].scope;
        let within = self.rules[idx].within_ns();
        let steps = self.rules[idx].sequence.clone();
        let scope_key = self.scope_key(ev, scope, graph);
        let pkey = (idx, scope_key);

        // Expire a stale partial before considering this event.
        if let Some(p) = self.partials.get(&pkey) {
            if ev.ts_ns.saturating_sub(p.first_ts) > within {
                self.partials.remove(&pkey);
            }
        }

        // Advance an existing partial if this event matches its next step.
        if let Some(p) = self.partials.get_mut(&pkey) {
            if steps[p.step].matches(ev) {
                p.step += 1;
                p.last_ts = ev.ts_ns;
                if p.step == steps.len() {
                    self.partials.remove(&pkey);
                    return Some(self.make_signal(idx, scope_key, ev.ts_ns));
                }
                return None;
            }
        }

        // Otherwise, does this event start the sequence?
        if steps[0].matches(ev) {
            // A one-step sequence completes immediately.
            if steps.len() == 1 {
                return Some(self.make_signal(idx, scope_key, ev.ts_ns));
            }
            self.partials.insert(
                pkey,
                Partial {
                    step: 1,
                    first_ts: ev.ts_ns,
                    last_ts: ev.ts_ns,
                },
            );
        }
        None
    }

    fn make_signal(&self, idx: usize, key: ProcKey, ts_ns: u64) -> Signal {
        let r = &self.rules[idx];
        Signal::new(
            self.signal_id(idx),
            r.score,
            self.attack[idx],
            key,
            ts_ns,
            if r.description.is_empty() {
                r.name.clone()
            } else {
                r.description.clone()
            },
        )
    }

    /// Drop sequence state for processes gone from the graph (bounds memory,
    /// mirroring Engine::reap).
    pub fn reap(&mut self, graph: &ProcessGraph) {
        self.partials.retain(|(_, key), _| graph.get(key).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(json: &str) -> Event {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn single_event_condition_matches() {
        let c: Condition = serde_yaml::from_str("event: exec\nfilename_prefix: /tmp/").unwrap();
        assert!(c.matches(&ev(
            r#"{"ts_ns":1,"type":1,"tgid":1,"ppid":0,"start_boottime":0,"filename":"/tmp/x"}"#
        )));
        assert!(!c.matches(&ev(
            r#"{"ts_ns":1,"type":1,"tgid":1,"ppid":0,"start_boottime":0,"filename":"/usr/bin/ls"}"#
        )));
        // wrong event type
        assert!(!c.matches(&ev(
            r#"{"ts_ns":1,"type":2,"tgid":1,"ppid":0,"start_boottime":0}"#
        )));
    }

    #[test]
    fn to_root_and_container_conditions() {
        let c: Condition = serde_yaml::from_str("event: cred_change\nto_root: true").unwrap();
        assert!(c.matches(&ev(
            r#"{"ts_ns":1,"type":4,"tgid":1,"ppid":0,"start_boottime":0,"euid":0,"old_euid":1000}"#
        )));
        assert!(!c.matches(&ev(
            r#"{"ts_ns":1,"type":4,"tgid":1,"ppid":0,"start_boottime":0,"euid":0,"old_euid":0}"#
        )));

        let c2: Condition = serde_yaml::from_str("event: exec\nin_container: true").unwrap();
        assert!(c2.matches(&ev(
            r#"{"ts_ns":1,"type":1,"tgid":1,"ppid":0,"start_boottime":0,"container":"docker:abc"}"#
        )));
        assert!(!c2.matches(&ev(
            r#"{"ts_ns":1,"type":1,"tgid":1,"ppid":0,"start_boottime":0}"#
        )));
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_ns("30s"), Some(30_000_000_000));
        assert_eq!(parse_duration_ns("500ms"), Some(500_000_000));
        assert_eq!(parse_duration_ns("2m"), Some(120_000_000_000));
        assert_eq!(parse_duration_ns("nonsense"), None);
    }

    #[test]
    fn validation_rejects_bad_rules() {
        let no_body: Rule = serde_yaml::from_str("name: x\nscore: 10").unwrap();
        assert!(no_body.validate().is_err());
        let both: Rule = serde_yaml::from_str(
            "name: x\nscore: 10\nmatch:\n  event: exec\nsequence:\n  - event: exit",
        )
        .unwrap();
        assert!(both.validate().is_err());
        let bad_event: Rule =
            serde_yaml::from_str("name: x\nscore: 10\nmatch:\n  event: nope").unwrap();
        assert!(bad_event.validate().is_err());
    }
}
