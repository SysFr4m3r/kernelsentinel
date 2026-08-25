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
    /// A filesystem path worth inspecting for *what* this is, when the signal
    /// identifies one. Behaviour says a payload ran; content says which payload.
    /// For a fileless exec this is `/proc/<pid>/exe`, which still resolves to a
    /// memfd image that was never on disk.
    pub target: Option<String>,
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
            target: None,
        }
    }

    /// Attach a path worth scanning for content.
    pub fn with_target(mut self, path: impl Into<String>) -> Self {
        let p = path.into();
        if !p.is_empty() {
            self.target = Some(p);
        }
        self
    }
}
