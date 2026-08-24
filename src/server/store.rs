//! Central fleet store. Holds each reporting host's incidents and derives a
//! per-host risk score. In-memory and bounded for this first increment;
//! persistence (sqlite/file) is future work.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// One line of the NDJSON journal.
#[derive(Serialize, Deserialize)]
struct PersistLine {
    host: String,
    #[serde(default)]
    kernel: String,
    #[serde(default)]
    ip: String,
    received: u64,
    record: serde_json::Value,
}

/// One incident as received from an agent: the agent's own IncidentRecord JSON,
/// kept opaque here (re-serialized to the dashboard as-is) plus the fields the
/// fleet view needs to rank and summarize without re-parsing everything.
#[derive(Clone, Serialize)]
pub struct StoredIncident {
    pub severity: String,
    pub score: u32,
    /// The full incident record, passed through to the detail view untouched.
    pub record: serde_json::Value,
    /// Server receive time (epoch seconds).
    pub received: u64,
}

#[derive(Default)]
pub struct HostState {
    pub incidents: Vec<StoredIncident>,
    pub last_seen: u64,
    pub kernel: String,
    pub ip: String,
}

/// Keep at most this many incidents per host (newest wins). A monitoring server
/// must not grow without bound just because a host is noisy.
const MAX_PER_HOST: usize = 500;

/// Severity band from a numeric score, matching the engine's bands.
pub fn band(score: u32) -> &'static str {
    match score {
        0 => "OK",
        1..=24 => "INFO",
        25..=49 => "LOW",
        50..=74 => "MEDIUM",
        75..=89 => "HIGH",
        _ => "CRITICAL",
    }
}

#[derive(Serialize)]
pub struct HostSummary {
    pub host: String,
    pub score: u32,
    pub band: &'static str,
    pub n: usize,
    pub counts: HashMap<String, usize>,
    pub last_seen: u64,
    pub kernel: String,
    pub ip: String,
}

pub struct Store {
    hosts: Mutex<HashMap<String, HostState>>,
    /// Append-only NDJSON journal so incidents survive a restart. None = memory
    /// only. Each line is one persisted record; the store is rebuilt from it on
    /// startup and the file is compacted to the retained set.
    journal: Mutex<Option<std::fs::File>>,
    journal_path: Option<PathBuf>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self {
            hosts: Mutex::new(HashMap::new()),
            journal: Mutex::new(None),
            journal_path: None,
        }
    }

    /// A store backed by an NDJSON journal at `path`: load what is already there,
    /// then append new incidents so reports survive a restart. On load the store
    /// is capped per host, and the journal is compacted to exactly the retained
    /// set so it cannot grow without bound.
    pub fn persistent(path: &str) -> std::io::Result<Self> {
        let store = Store::new();
        let pb = PathBuf::from(path);

        if let Ok(text) = std::fs::read_to_string(&pb) {
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(rec) = serde_json::from_str::<PersistLine>(line) {
                    store.ingest_inner(&rec.host, &rec.kernel, &rec.ip, rec.record, rec.received);
                }
            }
        }

        // Compact: rewrite the journal from the (now bounded) in-memory state.
        let mut f = std::fs::File::create(&pb)?;
        {
            let hosts = store.hosts.lock().unwrap();
            for (host, state) in hosts.iter() {
                for inc in &state.incidents {
                    let line = PersistLine {
                        host: host.clone(),
                        kernel: state.kernel.clone(),
                        ip: state.ip.clone(),
                        received: inc.received,
                        record: inc.record.clone(),
                    };
                    writeln!(f, "{}", serde_json::to_string(&line).unwrap())?;
                }
            }
        }
        f.flush()?;

        let mut store = store;
        store.journal = Mutex::new(Some(std::fs::OpenOptions::new().append(true).open(&pb)?));
        store.journal_path = Some(pb);
        Ok(store)
    }

    /// Record one incident from `host`. `record` is the agent's incident JSON.
    pub fn ingest(&self, host: &str, kernel: &str, ip: &str, record: serde_json::Value) {
        // Journal first (durability), then apply to memory.
        if let Ok(mut j) = self.journal.lock() {
            if let Some(f) = j.as_mut() {
                let line = PersistLine {
                    host: host.to_string(),
                    kernel: kernel.to_string(),
                    ip: ip.to_string(),
                    received: epoch(),
                    record: record.clone(),
                };
                if let Ok(s) = serde_json::to_string(&line) {
                    let _ = writeln!(f, "{s}");
                }
            }
        }
        self.ingest_inner(host, kernel, ip, record, epoch());
    }

    fn ingest_inner(
        &self,
        host: &str,
        kernel: &str,
        ip: &str,
        record: serde_json::Value,
        now: u64,
    ) {
        let severity = record
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("INFO")
            .to_string();
        let score = record.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        let mut hosts = self.hosts.lock().unwrap();
        let state = hosts.entry(host.to_string()).or_default();
        state.last_seen = now;
        if !kernel.is_empty() {
            state.kernel = kernel.to_string();
        }
        if !ip.is_empty() {
            state.ip = ip.to_string();
        }
        state.incidents.push(StoredIncident {
            severity,
            score,
            record,
            received: now,
        });
        // Bound: drop oldest beyond the cap.
        let len = state.incidents.len();
        if len > MAX_PER_HOST {
            state.incidents.drain(0..len - MAX_PER_HOST);
        }
    }

    /// A host's score is its worst live incident -- the triage-relevant "how bad
    /// is this host right now" number. Sorting the fleet by it puts the hosts
    /// that need attention first.
    fn host_score(state: &HostState) -> u32 {
        state.incidents.iter().map(|i| i.score).max().unwrap_or(0)
    }

    /// Fleet summary: every host with its score, ranked worst-first.
    pub fn fleet(&self) -> Vec<HostSummary> {
        let hosts = self.hosts.lock().unwrap();
        let mut out: Vec<HostSummary> = hosts
            .iter()
            .map(|(host, state)| {
                let score = Self::host_score(state);
                let mut counts: HashMap<String, usize> = HashMap::new();
                for i in &state.incidents {
                    *counts.entry(i.severity.clone()).or_insert(0) += 1;
                }
                HostSummary {
                    host: host.clone(),
                    score,
                    band: band(score),
                    n: state.incidents.len(),
                    counts,
                    last_seen: state.last_seen,
                    kernel: state.kernel.clone(),
                    ip: state.ip.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.host.cmp(&b.host)));
        out
    }

    /// One host's incidents, newest first.
    pub fn host_incidents(&self, host: &str) -> Option<Vec<serde_json::Value>> {
        let hosts = self.hosts.lock().unwrap();
        hosts
            .get(host)
            .map(|s| s.incidents.iter().rev().map(|i| i.record.clone()).collect())
    }
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_score_is_worst_incident() {
        let s = Store::new();
        s.ingest(
            "h1",
            "6.8",
            "10.0.0.1",
            json!({"severity":"LOW","score":40}),
        );
        s.ingest(
            "h1",
            "6.8",
            "10.0.0.1",
            json!({"severity":"CRITICAL","score":100}),
        );
        s.ingest(
            "h1",
            "6.8",
            "10.0.0.1",
            json!({"severity":"MEDIUM","score":50}),
        );
        let fleet = s.fleet();
        assert_eq!(fleet.len(), 1);
        assert_eq!(fleet[0].score, 100);
        assert_eq!(fleet[0].band, "CRITICAL");
        assert_eq!(fleet[0].n, 3);
    }

    #[test]
    fn fleet_ranks_worst_first() {
        let s = Store::new();
        s.ingest("quiet", "", "", json!({"severity":"LOW","score":25}));
        s.ingest("bad", "", "", json!({"severity":"CRITICAL","score":95}));
        s.ingest("mid", "", "", json!({"severity":"MEDIUM","score":60}));
        let f = s.fleet();
        assert_eq!(f[0].host, "bad");
        assert_eq!(f[1].host, "mid");
        assert_eq!(f[2].host, "quiet");
    }

    #[test]
    fn band_matches_engine() {
        assert_eq!(band(0), "OK");
        assert_eq!(band(40), "LOW");
        assert_eq!(band(50), "MEDIUM");
        assert_eq!(band(100), "CRITICAL");
    }
}
