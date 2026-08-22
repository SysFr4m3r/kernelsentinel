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
    pub pid: u32,
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
}

/// Stable NDJSON schema, version-tagged so downstream consumers can pin it.
#[derive(Serialize)]
pub struct IncidentRecord {
    pub schema: &'static str,
    pub ts_ns: u64,
    pub severity: &'static str,
    pub score: u32,
    pub score_breakdown: ScoreBreakdown,
    pub subject: SubjectRecord,
    pub lineage: Vec<String>,
    pub attack: Vec<String>,
    pub signals: Vec<SignalRecord>,
}

impl IncidentRecord {
    pub fn from_incident(inc: &Incident, graph: &ProcessGraph) -> Self {
        let subject_node = graph.get(&inc.subject);
        let subject = SubjectRecord {
            pid: inc.subject.pid,
            start_boottime: inc.subject.start_boottime,
            comm: subject_node.map(|n| n.comm.clone()).unwrap_or_default(),
            exe: subject_node.map(|n| n.exe.clone()).unwrap_or_default(),
            uid: subject_node.map(|n| n.uid).unwrap_or(0),
        };

        // Lineage root-first, matching the human renderer.
        let lineage: Vec<String> = graph
            .ancestry(&inc.subject)
            .iter()
            .rev()
            .map(|n| format!("{}({})", n.comm, n.key.pid))
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
                pid: s.key.pid,
            })
            .collect();

        // The incident timestamp is its most recent signal.
        let ts_ns = inc.signals.iter().map(|s| s.ts_ns).max().unwrap_or(0);

        IncidentRecord {
            schema: "kernelsentinel.incident/v1",
            ts_ns,
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
            attack: inc.attack.clone(),
            signals,
        }
    }

    pub fn to_ndjson(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#))
    }
}
