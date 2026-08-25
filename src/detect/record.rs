//! Machine-readable incident output. The human renderer (alert.rs) is for a
//! terminal; this is the schema a SIEM or automated pipeline consumes -- one
//! JSON object per incident, self-contained, with the lineage resolved to names
//! so a downstream consumer needs nothing from the graph.

use serde::Serialize;

use crate::graph::ProcessGraph;

use super::Incident;

#[derive(Serialize)]
pub struct SignalRecord {
    pub id: &'static str,
    pub score: u32,
    pub detail: String,
    pub attack: Vec<&'static str>,
    pub ts_ns: u64,
    /// Wall-clock time this signal fired, epoch milliseconds. Absent when
    /// replaying a capture: the recording never stored the boot->wall offset,
    /// so any wall time we printed would be invented. `ts_ns` differences stay
    /// exact either way, which is what an in-incident timeline needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    pub pid: u32,
    /// The command line of the process this signal fired on -- "which command
    /// actually did this". A detail like "SUID gained: /tmp/.x" says what
    /// happened; this says what ran.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
}

/// One process in the lineage, with enough detail to read the chain as a story
/// rather than a list of names.
#[derive(Serialize)]
pub struct LineageRecord {
    pub pid: u32,
    pub comm: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub exe: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
}

#[derive(Serialize)]
pub struct ScoreBreakdown {
    pub base: u32,
    pub chain_bonus: u32,
    pub context_mult: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_note: Option<String>,
}

#[derive(Serialize)]
pub struct SubjectRecord {
    pub pid: u32,
    pub start_boottime: u64,
    pub comm: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub exe: String,
    pub uid: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cmdline: String,
}

/// Stable NDJSON schema, version-tagged so downstream consumers can pin it.
#[derive(Serialize)]
pub struct IncidentRecord {
    pub schema: &'static str,
    pub ts_ns: u64,
    /// Wall-clock time of the most recent signal, epoch milliseconds. See
    /// `SignalRecord::ts` for why it can be absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<u64>,
    pub severity: &'static str,
    pub score: u32,
    pub score_breakdown: ScoreBreakdown,
    pub subject: SubjectRecord,
    pub lineage: Vec<String>,
    /// Same chain as `lineage`, but structured and carrying each process's
    /// command line. `lineage` stays as-is so v1 consumers keep working.
    pub lineage_detail: Vec<LineageRecord>,
    pub attack: Vec<String>,
    pub signals: Vec<SignalRecord>,
}

/// Render a process's argv as a shell-ish one-liner. argv is bounded in-kernel
/// (MAX_ARGV), so this is already short; cap it again so one pathological
/// command cannot dominate an alert.
fn cmdline_of(graph: &ProcessGraph, key: &crate::graph::ProcKey) -> String {
    const MAX: usize = 200;
    let Some(node) = graph.get(key) else {
        return String::new();
    };
    if node.argv.is_empty() {
        return String::new();
    }
    let joined = node.argv.join(" ");
    if joined.len() > MAX {
        let mut cut = MAX;
        while cut > 0 && !joined.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &joined[..cut])
    } else {
        joined
    }
}

impl IncidentRecord {
    /// `clock` converts the kernel's boot-relative timestamps to wall clock.
    /// `None` when replaying a capture, where no honest conversion exists.
    pub fn from_incident(
        inc: &Incident,
        graph: &ProcessGraph,
        clock: Option<&crate::clock::BootClock>,
    ) -> Self {
        let subject_node = graph.get(&inc.subject);
        let subject = SubjectRecord {
            pid: inc.subject.pid,
            start_boottime: inc.subject.start_boottime,
            comm: subject_node.map(|n| n.comm.clone()).unwrap_or_default(),
            exe: subject_node.map(|n| n.exe.clone()).unwrap_or_default(),
            uid: subject_node.map(|n| n.uid).unwrap_or(0),
            cmdline: cmdline_of(graph, &inc.subject),
        };

        // Lineage root-first, matching the human renderer.
        let lineage: Vec<String> = graph
            .ancestry(&inc.subject)
            .iter()
            .rev()
            .map(|n| format!("{}({})", n.comm, n.key.pid))
            .collect();

        let lineage_detail: Vec<LineageRecord> = graph
            .ancestry(&inc.subject)
            .iter()
            .rev()
            .map(|n| LineageRecord {
                pid: n.key.pid,
                comm: n.comm.clone(),
                exe: n.exe.clone(),
                cmdline: cmdline_of(graph, &n.key),
            })
            .collect();

        let signals = inc
            .signals
            .iter()
            .map(|s| SignalRecord {
                id: s.id,
                score: s.score,
                detail: s.detail.clone(),
                attack: s.attack.to_vec(),
                ts_ns: s.ts_ns,
                ts: clock.map(|c| c.to_epoch_ms(s.ts_ns)),
                pid: s.key.pid,
                cmdline: cmdline_of(graph, &s.key),
            })
            .collect();

        // The incident timestamp is its most recent signal.
        let ts_ns = inc.signals.iter().map(|s| s.ts_ns).max().unwrap_or(0);

        IncidentRecord {
            schema: "kernelsentinel.incident/v1",
            ts_ns,
            ts: clock.map(|c| c.to_epoch_ms(ts_ns)),
            severity: inc.score.severity.label(),
            score: inc.score.total,
            score_breakdown: ScoreBreakdown {
                base: inc.score.base,
                chain_bonus: inc.score.chain_bonus,
                context_mult: inc.score.context_mult,
                context_note: inc.score.context_note.clone(),
            },
            subject,
            lineage,
            lineage_detail,
            attack: inc.attack.clone(),
            signals,
        }
    }

    pub fn to_ndjson(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#))
    }
}
