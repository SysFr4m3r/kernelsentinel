//! A signal is one scored observation about a process. Detections produce
//! signals; the engine combines the signals in a lineage into an incident.

use crate::graph::ProcKey;

/// A single detection firing on one process.
#[derive(Clone, Debug)]
pub struct Signal {
    /// Stable identifier, e.g. "suid_create".
    pub id: &'static str,
    /// Base contribution to the risk score, before chain/context adjustment.
    pub score: u32,
    /// Human-readable, with the specifics filled in.
    pub detail: String,
    /// MITRE ATT&CK technique ids.
    pub attack: &'static [&'static str],
    pub ts_ns: u64,
    /// The process this fired on.
    pub key: ProcKey,
}

impl Signal {
    pub fn new(
        id: &'static str,
        score: u32,
        attack: &'static [&'static str],
        key: ProcKey,
        ts_ns: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            score,
            attack,
            key,
            ts_ns,
            detail: detail.into(),
        }
    }
}
