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
    #[serde(default)]
    id: u64,
    host: String,
    #[serde(default)]
    kernel: String,
    #[serde(default)]
    ip: String,
    received: u64,
    record: serde_json::Value,
    #[serde(default)]
    resolved: bool,
    #[serde(default)]
    resolved_by: String,
    #[serde(default)]
    resolved_at: u64,
    #[serde(default)]
    note: String,
}

/// One incident as received from an agent: the agent's own IncidentRecord JSON,
/// kept opaque here (re-serialized to the dashboard as-is) plus the fields the
/// fleet view needs to rank and summarize without re-parsing everything.
#[derive(Clone, Serialize)]
pub struct StoredIncident {
    /// Server-assigned stable id, for resolution.
    pub id: u64,
    pub severity: String,
    pub score: u32,
    /// The full incident record, passed through to the detail view untouched.
    pub record: serde_json::Value,
    /// Server receive time (epoch seconds).
    pub received: u64,
    /// Triage state. A resolved incident no longer counts toward the host score.
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub resolved_by: String,
    #[serde(default)]
    pub resolved_at: u64,
    #[serde(default)]
    pub note: String,
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
    next_id: Mutex<u64>,
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
            next_id: Mutex::new(1),
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
                    store.replay(rec);
                }
            }
        }

        // Compact: rewrite the journal from the (now bounded) in-memory state.
        let mut f = std::fs::File::create(&pb)?;
        {
            let hosts = store.hosts.lock().unwrap();
            for (host, state) in hosts.iter() {
                for inc in &state.incidents {
                    writeln!(
                        f,
                        "{}",
                        serde_json::to_string(&persist_line(host, state, inc)).unwrap()
                    )?;
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
        let id = {
            let mut n = self.next_id.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        };
        let now = epoch();
        let inc = StoredIncident {
            id,
            severity: record
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("INFO")
                .to_string(),
            score: record.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            record,
            received: now,
            resolved: false,
            resolved_by: String::new(),
            resolved_at: 0,
            note: String::new(),
        };

        // Journal (durability) then apply.
        if let Ok(mut j) = self.journal.lock() {
            if let Some(f) = j.as_mut() {
                let line = PersistLine {
                    id: inc.id,
                    host: host.to_string(),
                    kernel: kernel.to_string(),
                    ip: ip.to_string(),
                    received: now,
                    record: inc.record.clone(),
                    resolved: false,
                    resolved_by: String::new(),
                    resolved_at: 0,
                    note: String::new(),
                };
                if let Ok(s) = serde_json::to_string(&line) {
                    let _ = writeln!(f, "{s}");
                }
            }
        }
        self.apply(host, kernel, ip, now, inc);
    }

    /// Reload one journal line into memory (no re-journaling).
    fn replay(&self, rec: PersistLine) {
        {
            let mut n = self.next_id.lock().unwrap();
            if rec.id >= *n {
                *n = rec.id + 1;
            }
        }
        let inc = StoredIncident {
            id: rec.id,
            severity: rec
                .record
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("INFO")
                .to_string(),
            score: rec
                .record
                .get("score")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32,
            record: rec.record,
            received: rec.received,
            resolved: rec.resolved,
            resolved_by: rec.resolved_by,
            resolved_at: rec.resolved_at,
            note: rec.note,
        };
        self.apply(&rec.host, &rec.kernel, &rec.ip, rec.received, inc);
    }

    fn apply(&self, host: &str, kernel: &str, ip: &str, now: u64, inc: StoredIncident) {
        let mut hosts = self.hosts.lock().unwrap();
        let state = hosts.entry(host.to_string()).or_default();
        state.last_seen = state.last_seen.max(now);
        if !kernel.is_empty() {
            state.kernel = kernel.to_string();
        }
        if !ip.is_empty() {
            state.ip = ip.to_string();
        }
        state.incidents.push(inc);
        let len = state.incidents.len();
        if len > MAX_PER_HOST {
            state.incidents.drain(0..len - MAX_PER_HOST);
        }
    }

    /// Mark an incident resolved. Writes only to the central record -- never to a
    /// host. The host score counts unresolved incidents only, so resolving the
    /// worst one drops the score to the next. Rewrites the journal so the
    /// resolution survives a restart.
    pub fn resolve(&self, host: &str, id: u64, by: &str, note: &str) -> bool {
        let found = {
            let mut hosts = self.hosts.lock().unwrap();
            let Some(state) = hosts.get_mut(host) else {
                return false;
            };
            match state.incidents.iter_mut().find(|i| i.id == id) {
                Some(inc) => {
                    inc.resolved = true;
                    inc.resolved_by = by.to_string();
                    inc.resolved_at = epoch();
                    inc.note = note.to_string();
                    true
                }
                None => false,
            }
        };
        if found {
            self.rewrite_journal();
        }
        found
    }

    /// Rewrite the journal from memory (after a resolution). Resolutions are
    /// infrequent admin actions, so O(n) is fine.
    fn rewrite_journal(&self) {
        let Some(path) = &self.journal_path else {
            return;
        };
        let hosts = self.hosts.lock().unwrap();
        if let Ok(mut f) = std::fs::File::create(path) {
            for (host, state) in hosts.iter() {
                for inc in &state.incidents {
                    if let Ok(s) = serde_json::to_string(&persist_line(host, state, inc)) {
                        let _ = writeln!(f, "{s}");
                    }
                }
            }
            let _ = f.flush();
        }
    }

    /// A host's score is its worst live incident -- the triage-relevant "how bad
    /// is this host right now" number. Sorting the fleet by it puts the hosts
    /// that need attention first.
    fn host_score(state: &HostState) -> u32 {
        state
            .incidents
            .iter()
            .filter(|i| !i.resolved)
            .map(|i| i.score)
            .max()
            .unwrap_or(0)
    }

    /// Fleet summary: every host with its score, ranked worst-first.
    pub fn fleet(&self) -> Vec<HostSummary> {
        let hosts = self.hosts.lock().unwrap();
        let mut out: Vec<HostSummary> = hosts
            .iter()
            .map(|(host, state)| {
                let score = Self::host_score(state);
                let mut counts: HashMap<String, usize> = HashMap::new();
                let mut open = 0usize;
                for i in state.incidents.iter().filter(|i| !i.resolved) {
                    *counts.entry(i.severity.clone()).or_insert(0) += 1;
                    open += 1;
                }
                HostSummary {
                    host: host.clone(),
                    score,
                    band: band(score),
                    n: open,
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
        hosts.get(host).map(|s| {
            s.incidents
                .iter()
                .rev()
                .map(|i| {
                    let mut v = i.record.clone();
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("_id".into(), i.id.into());
                        obj.insert("_resolved".into(), i.resolved.into());
                        obj.insert("_resolved_by".into(), i.resolved_by.clone().into());
                        obj.insert("_resolved_at".into(), i.resolved_at.into());
                        obj.insert("_note".into(), i.note.clone().into());
                    }
                    v
                })
                .collect()
        })
    }
}

fn persist_line(host: &str, state: &HostState, inc: &StoredIncident) -> PersistLine {
    PersistLine {
        id: inc.id,
        host: host.to_string(),
        kernel: state.kernel.clone(),
        ip: state.ip.clone(),
        received: inc.received,
        record: inc.record.clone(),
        resolved: inc.resolved,
        resolved_by: inc.resolved_by.clone(),
        resolved_at: inc.resolved_at,
        note: inc.note.clone(),
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
    fn resolving_worst_drops_score_to_next() {
        let s = Store::new();
        s.ingest("h", "", "", json!({"severity":"CRITICAL","score":100}));
        s.ingest("h", "", "", json!({"severity":"MEDIUM","score":50}));
        assert_eq!(s.fleet()[0].score, 100);
        assert_eq!(s.fleet()[0].n, 2);

        // Resolve the worst -> score drops to the next, open count falls.
        let worst_id = 1; // first ingested
        assert!(s.resolve("h", worst_id, "admin", "false positive"));
        assert_eq!(s.fleet()[0].score, 50, "score should drop to next-worst");
        assert_eq!(s.fleet()[0].n, 1, "resolved incident is not open");

        // Resolving a missing incident fails.
        assert!(!s.resolve("h", 999, "admin", ""));
    }

    #[test]
    fn band_matches_engine() {
        assert_eq!(band(0), "OK");
        assert_eq!(band(40), "LOW");
        assert_eq!(band(50), "MEDIUM");
        assert_eq!(band(100), "CRITICAL");
    }
}
