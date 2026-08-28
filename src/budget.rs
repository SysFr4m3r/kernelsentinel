//! Alert budget: how much noise this makes on a host where nothing happened.
//!
//! The README claims a few high-signal alerts rather than a syscall firehose,
//! and until now nothing measured that. The attack suite proves detections fire;
//! the noise suite proves five short scenarios stay quiet. Neither answers the
//! question an operator actually decides on: *how many alerts will I get per day
//! on a real machine, and what are they?* A tool that catches everything and
//! pages twice a day gets muted in week one, at which point detection quality
//! stops mattering.
//!
//! # What counts as a false positive
//!
//! Nothing here can label ground truth, so the definition is operational and the
//! operator supplies it: **record a host doing ordinary work, and every alert in
//! that capture is a false positive by construction.** The capture is the
//! assertion. That is why this reads a raw capture rather than a stream of
//! incidents -- the same evidence can be re-measured at a different floor or
//! against a different baseline, and the numbers stay comparable.
//!
//! # Why one pass per floor
//!
//! Reporting is stateful: an incident is emitted only when a lineage crosses
//! into a higher severity band than it has already reported. That interacts with
//! the floor -- a subject going info -> medium emits twice at the info floor and
//! once at the medium floor -- so the counts cannot be derived from a single
//! pass by filtering afterwards. Each floor gets its own replay with its own
//! engine.

use std::collections::HashMap;

use serde::Serialize;

use crate::decoded::Event;
use crate::detect::{Baseline, Engine, Severity};
use crate::graph::ProcessGraph;

/// Extrapolating a daily rate from a short recording is the same mistake the
/// baseline used to make with a single sighting. Below this, the rate is
/// reported as unknown rather than multiplied up.
pub const MIN_RELIABLE_SECS: u64 = 3600;

const NS_PER_SEC: f64 = 1_000_000_000.0;

#[derive(Serialize, Clone)]
pub struct FloorRow {
    pub floor: &'static str,
    pub incidents: usize,
    /// Alerts per day at this floor. `None` when the capture is too short to
    /// extrapolate honestly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub per_day: Option<f64>,
}

#[derive(Serialize, Clone)]
pub struct Offender {
    pub name: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct Budget {
    pub events: u64,
    pub parse_errors: u64,
    pub duration_secs: f64,
    pub events_per_sec: f64,
    /// True when the capture is long enough for the per-day rates to mean
    /// something. Everything below is still reported when false; only the
    /// extrapolation is withheld.
    pub extrapolation_reliable: bool,
    pub floors: Vec<FloorRow>,
    /// What produced the alerts at the operational floor, so a number turns
    /// into something to fix -- a detector to tighten, or a pair to baseline.
    pub by_signal: Vec<Offender>,
    pub by_subject: Vec<Offender>,
    /// Present when a baseline was supplied: the same measurement without it,
    /// so the reduction is visible rather than asserted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub without_baseline: Option<Vec<FloorRow>>,
}

pub const FLOORS: [Severity; 5] = [
    Severity::Info,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

/// One replay at one floor.
struct Pass {
    incidents: usize,
    by_signal: HashMap<String, usize>,
    by_subject: HashMap<String, usize>,
    events: u64,
    parse_errors: u64,
    first_ns: u64,
    last_ns: u64,
}

/// Build a fresh engine for one pass. The baseline and rules are loaded per
/// pass rather than shared: each floor needs its own engine with its own
/// reporting state, and re-reading two small files is cheaper than making every
/// piece of engine state cloneable for the sake of an analysis command.
fn engine_for(floor: Severity, baseline: Option<&str>, rules: Option<&str>) -> Engine {
    let mut e = Engine::new(floor);
    if let Some(path) = baseline {
        if let Ok(b) = Baseline::load(path) {
            e = e.with_baseline(b);
        }
    }
    if let Some(dir) = rules {
        if let Ok(r) = crate::detect::load_rules(dir) {
            e = e.with_rules(crate::detect::RuleSet::new(r));
        }
    }
    e
}

fn replay_at(lines: &str, floor: Severity, baseline: Option<&str>, rules: Option<&str>) -> Pass {
    let mut graph = ProcessGraph::new(usize::MAX, std::time::Duration::from_secs(u64::MAX / 2));
    let mut engine = engine_for(floor, baseline, rules);

    let mut p = Pass {
        incidents: 0,
        by_signal: HashMap::new(),
        by_subject: HashMap::new(),
        events: 0,
        parse_errors: 0,
        first_ns: 0,
        last_ns: 0,
    };

    for line in lines.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ev: Event = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => {
                p.parse_errors += 1;
                continue;
            }
        };
        p.events += 1;
        if ev.ts_ns != 0 {
            p.first_ns = if p.first_ns == 0 {
                ev.ts_ns
            } else {
                p.first_ns.min(ev.ts_ns)
            };
            p.last_ns = p.last_ns.max(ev.ts_ns);
        }
        graph.apply(&ev);
        if let Some(inc) = engine.on_event(&ev, &graph) {
            p.incidents += 1;
            for s in &inc.signals {
                *p.by_signal.entry(s.id.to_string()).or_insert(0) += 1;
            }
            let subject = graph
                .get(&inc.subject)
                .map(|n| {
                    if n.exe.is_empty() {
                        n.comm.clone()
                    } else {
                        n.exe.clone()
                    }
                })
                .unwrap_or_else(|| "<unknown>".to_string());
            *p.by_subject.entry(subject).or_insert(0) += 1;
        }
    }
    p
}

fn top(map: &HashMap<String, usize>, n: usize) -> Vec<Offender> {
    let mut v: Vec<Offender> = map
        .iter()
        .map(|(name, count)| Offender {
            name: name.clone(),
            count: *count,
        })
        .collect();
    // Count descending, then name, so the output is stable run to run.
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(n);
    v
}

fn per_day(incidents: usize, duration_secs: f64, reliable: bool) -> Option<f64> {
    if !reliable || duration_secs <= 0.0 {
        return None;
    }
    Some(incidents as f64 / (duration_secs / 86_400.0))
}

/// Measure a capture at every floor, and against a baseline if one is given.
///
/// `attribution_floor` decides which pass the offender breakdown comes from:
/// the floor an operator actually alerts on, since that is the noise they would
/// be paged for.
pub fn measure(
    lines: &str,
    baseline: Option<&str>,
    rules: Option<&str>,
    attribution_floor: Severity,
) -> Budget {
    let passes: Vec<(Severity, Pass)> = FLOORS
        .iter()
        .map(|f| (*f, replay_at(lines, *f, baseline, rules)))
        .collect();

    // Event counts and the time span are properties of the capture, identical
    // in every pass; take them from the first.
    let any = &passes[0].1;
    let duration_secs = any.last_ns.saturating_sub(any.first_ns) as f64 / NS_PER_SEC;
    let reliable = duration_secs >= MIN_RELIABLE_SECS as f64;

    let floors: Vec<FloorRow> = passes
        .iter()
        .map(|(f, p)| FloorRow {
            floor: f.label(),
            incidents: p.incidents,
            per_day: per_day(p.incidents, duration_secs, reliable),
        })
        .collect();

    let attributed = passes
        .iter()
        .find(|(f, _)| *f == attribution_floor)
        .map(|(_, p)| p)
        .expect("attribution_floor must be one of FLOORS");

    // Re-measure without the baseline so its effect is shown, not claimed.
    let without_baseline = baseline.map(|_| {
        FLOORS
            .iter()
            .map(|f| {
                let p = replay_at(lines, *f, None, rules);
                FloorRow {
                    floor: f.label(),
                    incidents: p.incidents,
                    per_day: per_day(p.incidents, duration_secs, reliable),
                }
            })
            .collect()
    });

    Budget {
        events: any.events,
        parse_errors: any.parse_errors,
        duration_secs,
        events_per_sec: if duration_secs > 0.0 {
            any.events as f64 / duration_secs
        } else {
            0.0
        },
        extrapolation_reliable: reliable,
        floors,
        by_signal: top(&attributed.by_signal, 10),
        by_subject: top(&attributed.by_subject, 10),
        without_baseline,
    }
}

impl Budget {
    pub fn render(&self, attribution_floor: Severity) -> String {
        let mut o = String::new();
        o.push_str("\nalert budget\n\n");
        o.push_str(&format!(
            "  capture     {} events over {}, {:.1} events/sec\n",
            self.events,
            human_secs(self.duration_secs),
            self.events_per_sec
        ));
        if self.parse_errors > 0 {
            o.push_str(&format!(
                "              {} lines could not be parsed\n",
                self.parse_errors
            ));
        }
        o.push('\n');

        let has_rate = self.extrapolation_reliable;
        o.push_str(if has_rate {
            "  floor       incidents    per day\n"
        } else {
            "  floor       incidents\n"
        });
        for (i, row) in self.floors.iter().enumerate() {
            let base = self
                .without_baseline
                .as_ref()
                .and_then(|w| w.get(i))
                .map(|w| w.incidents);
            let delta = match base {
                Some(b) if b != row.incidents => format!("   (was {b} without the baseline)"),
                _ => String::new(),
            };
            match row.per_day {
                Some(d) => o.push_str(&format!(
                    "  {:<10}  {:>9}  {:>9.1}{}\n",
                    row.floor, row.incidents, d, delta
                )),
                None => o.push_str(&format!(
                    "  {:<10}  {:>9}{}\n",
                    row.floor, row.incidents, delta
                )),
            }
        }

        if !has_rate {
            o.push_str(&format!(
                "\n  The capture is shorter than {}, so a daily rate from it would be\n  \
                 invented rather than measured. Record a host doing its ordinary work\n  \
                 for a few hours and re-run.\n",
                human_secs(MIN_RELIABLE_SECS as f64)
            ));
        }

        if !self.by_signal.is_empty() {
            o.push_str(&format!(
                "\n  what fired at {}\n",
                attribution_floor.label().to_lowercase()
            ));
            for x in &self.by_signal {
                o.push_str(&format!("  {:>9}x  {}\n", x.count, x.name));
            }
        }
        if !self.by_subject.is_empty() {
            o.push_str("\n  who set it off\n");
            for x in &self.by_subject {
                o.push_str(&format!("  {:>9}x  {}\n", x.count, x.name));
            }
        }

        if self.floors.iter().any(|r| r.incidents > 0) {
            o.push_str(
                "\n  If nothing malicious happened while this was recorded, every incident\n  \
                 above is a false positive. The two lists say which detector to tighten or\n  \
                 which pair to teach a baseline.\n",
            );
        }
        o
    }
}

fn human_secs(s: f64) -> String {
    match s {
        s if s >= 86_400.0 => format!("{:.1}d", s / 86_400.0),
        s if s >= 3_600.0 => format!("{:.1}h", s / 3_600.0),
        s if s >= 60.0 => format!("{:.0}m", s / 60.0),
        s => format!("{s:.0}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture spanning `hours`, with one `sudo`-shaped escalation per hour.
    fn synthetic(hours: u64) -> String {
        let mut out = String::new();
        for i in 0..hours {
            let ts = i * 3_600_000_000_000u64;
            let pid = 1000 + i as u32;
            for line in [
                serde_json::json!({"ts_ns": ts, "type": 1, "tgid": pid, "ppid": 1,
                    "start_boottime": ts, "uid": 1000, "euid": 1000, "cgroup_id": 1,
                    "comm": "sudo", "filename": "/usr/bin/sudo", "argv": ["sudo", "id"]}),
                serde_json::json!({"ts_ns": ts + 1000, "type": 4, "tgid": pid, "ppid": 1,
                    "start_boottime": ts, "uid": 0, "euid": 0, "old_uid": 1000,
                    "old_euid": 1000, "cgroup_id": 1, "comm": "sudo",
                    "cap_effective": 0x1ffffffffff_u64, "old_cap_effective": 0}),
            ] {
                out.push_str(&line.to_string());
                out.push('\n');
            }
        }
        out
    }

    #[test]
    fn a_short_capture_reports_counts_but_refuses_to_extrapolate() {
        let b = measure(&synthetic(1), None, None, Severity::Medium);
        assert!(!b.extrapolation_reliable);
        assert!(
            b.floors.iter().all(|f| f.per_day.is_none()),
            "a rate from under an hour would be invented, not measured"
        );
        assert_eq!(b.events, 2, "counts are still reported");
        assert!(
            b.render(Severity::Medium)
                .contains("invented rather than measured")
        );
    }

    #[test]
    fn a_long_capture_extrapolates() {
        let b = measure(&synthetic(24), None, None, Severity::Medium);
        assert!(b.extrapolation_reliable);
        assert!(b.duration_secs > 82_000.0, "23 hours of span");
        for f in &b.floors {
            assert!(f.per_day.is_some());
        }
    }

    /// Raising the floor can only ever reduce the number of incidents. If this
    /// inverts, either the floor is not being applied or reporting state is
    /// leaking between passes.
    #[test]
    fn incidents_never_increase_with_the_floor() {
        let b = measure(&synthetic(24), None, None, Severity::Medium);
        for w in b.floors.windows(2) {
            assert!(
                w[1].incidents <= w[0].incidents,
                "{} had {} incidents but {} had {}",
                w[0].floor,
                w[0].incidents,
                w[1].floor,
                w[1].incidents
            );
        }
    }

    #[test]
    fn an_empty_capture_measures_nothing_without_panicking() {
        let b = measure("", None, None, Severity::Medium);
        assert_eq!(b.events, 0);
        assert_eq!(b.duration_secs, 0.0);
        assert_eq!(b.events_per_sec, 0.0);
        assert!(b.floors.iter().all(|f| f.incidents == 0));
        assert!(b.by_signal.is_empty() && b.by_subject.is_empty());
        assert!(!b.extrapolation_reliable);
    }

    #[test]
    fn unparseable_lines_are_counted_not_silently_dropped() {
        let mut text = synthetic(2);
        text.push_str("{not json\n");
        text.push('\n'); // blank lines are not errors
        let b = measure(&text, None, None, Severity::Medium);
        assert_eq!(b.parse_errors, 1);
        assert_eq!(b.events, 4);
        assert!(b.render(Severity::Medium).contains("could not be parsed"));
    }

    #[test]
    fn offenders_are_ranked_and_stable() {
        let mut m = HashMap::new();
        m.insert("b".to_string(), 3);
        m.insert("a".to_string(), 3);
        m.insert("c".to_string(), 9);
        let t = top(&m, 10);
        assert_eq!(t[0].name, "c");
        // Equal counts fall back to the name, so two runs agree.
        assert_eq!(t[1].name, "a");
        assert_eq!(t[2].name, "b");
        assert_eq!(top(&m, 1).len(), 1);
    }

    /// The measurement must attribute at the floor it was asked for, not at a
    /// fixed one -- the breakdown is meant to explain the alerts an operator
    /// would actually receive.
    #[test]
    fn attribution_follows_the_requested_floor() {
        let text = synthetic(24);
        let at_info = measure(&text, None, None, Severity::Info);
        let at_crit = measure(&text, None, None, Severity::Critical);
        let count = |b: &Budget| b.by_signal.iter().map(|o| o.count).sum::<usize>();
        assert!(
            count(&at_info) >= count(&at_crit),
            "a lower floor must attribute at least as much"
        );
    }
}
