//! Central fleet store. Holds each reporting host's incidents and derives a
//! per-host risk score. In-memory and bounded for this first increment;
//! persistence (sqlite/file) is future work.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::Serialize;

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

#[derive(Serialize)]
pub struct AuditEntry {
    pub host: String,
    pub id: u64,
    pub severity: String,
    pub score: u32,
    pub resolved_by: String,
    pub resolved_at: u64,
    pub note: String,
    pub subject: String,
}

fn field_str(v: &serde_json::Value, key: &str, default: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or(default)
        .to_string()
}

fn subject_comm(v: &serde_json::Value) -> String {
    v.get("subject")
        .and_then(|s| s.get("comm"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string()
}

pub struct Store {
    /// In-memory working set (bounded) for fast fleet/host reads.
    hosts: Mutex<HashMap<String, HostState>>,
    /// sqlite connection for durable, queryable history. None = memory only.
    /// The full history lives here (for the audit trail and retention); memory
    /// holds only the recent per-host working set.
    db: Option<Mutex<Connection>>,
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
            db: None,
            next_id: Mutex::new(1),
        }
    }

    /// A store backed by a sqlite database at `path`: durable, queryable history
    /// that survives restarts. On open it optionally prunes incidents older than
    /// `retain_days` (0 = keep forever), then loads the recent per-host working
    /// set into memory. Full history stays in sqlite for the audit trail.
    pub fn persistent(path: &str, retain_days: u64) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS incidents (
                 id INTEGER PRIMARY KEY,
                 host TEXT NOT NULL, kernel TEXT, ip TEXT,
                 received INTEGER NOT NULL,
                 severity TEXT NOT NULL, score INTEGER NOT NULL,
                 record TEXT NOT NULL,
                 resolved INTEGER NOT NULL DEFAULT 0,
                 resolved_by TEXT DEFAULT '', resolved_at INTEGER DEFAULT 0,
                 note TEXT DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_host ON incidents(host);
             CREATE INDEX IF NOT EXISTS idx_resolved ON incidents(resolved, resolved_at);",
        )?;

        if retain_days > 0 {
            let cutoff = epoch().saturating_sub(retain_days * 86_400);
            conn.execute("DELETE FROM incidents WHERE received < ?1", [cutoff as i64])?;
        }

        let store = Store::new();

        // Load recent rows into the in-memory working set (ascending id so the
        // per-host cap keeps the newest).
        {
            let mut stmt = conn.prepare(
                "SELECT id, host, kernel, ip, received, record, resolved, resolved_by,                  resolved_at, note FROM incidents ORDER BY id ASC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)? as u64,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)? != 0,
                    r.get::<_, String>(7)?,
                    r.get::<_, i64>(8)? as u64,
                    r.get::<_, String>(9)?,
                ))
            })?;
            let mut max_id = 0u64;
            for row in rows.flatten() {
                let (id, host, kernel, ip, received, record, resolved, by, at, note) = row;
                max_id = max_id.max(id);
                let record: serde_json::Value =
                    serde_json::from_str(&record).unwrap_or(serde_json::Value::Null);
                let inc = StoredIncident {
                    id,
                    severity: field_str(&record, "severity", "INFO"),
                    score: record.get("score").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    record,
                    received,
                    resolved,
                    resolved_by: by,
                    resolved_at: at,
                    note,
                };
                store.apply(&host, &kernel, &ip, received, inc);
            }
            *store.next_id.lock().unwrap() = max_id + 1;
        }

        let mut store = store;
        store.db = Some(Mutex::new(conn));
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

        // Durable write to sqlite (if persistent), then apply to memory.
        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute(
                "INSERT INTO incidents (id, host, kernel, ip, received, severity, score, record)                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    inc.id as i64,
                    host,
                    kernel,
                    ip,
                    now as i64,
                    inc.severity,
                    inc.score as i64,
                    inc.record.to_string(),
                ],
            );
        }
        self.apply(host, kernel, ip, now, inc);
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
            if let Some(db) = &self.db {
                let conn = db.lock().unwrap();
                let _ = conn.execute(
                    "UPDATE incidents SET resolved = 1, resolved_by = ?1, resolved_at = ?2,                      note = ?3 WHERE id = ?4",
                    rusqlite::params![by, epoch() as i64, note, id as i64],
                );
            }
        }
        found
    }

    /// The resolution audit trail: recently-resolved incidents across the fleet,
    /// newest first. Queried from sqlite so it spans the full history, not just
    /// the in-memory working set.
    pub fn audit(&self, limit: usize) -> Vec<AuditEntry> {
        let Some(db) = &self.db else {
            // Memory-only fallback.
            let hosts = self.hosts.lock().unwrap();
            let mut out: Vec<AuditEntry> = hosts
                .iter()
                .flat_map(|(host, st)| {
                    st.incidents
                        .iter()
                        .filter(|i| i.resolved)
                        .map(move |i| AuditEntry {
                            host: host.clone(),
                            id: i.id,
                            severity: i.severity.clone(),
                            score: i.score,
                            resolved_by: i.resolved_by.clone(),
                            resolved_at: i.resolved_at,
                            note: i.note.clone(),
                            subject: subject_comm(&i.record),
                        })
                })
                .collect();
            out.sort_by_key(|a| std::cmp::Reverse(a.resolved_at));
            out.truncate(limit);
            return out;
        };
        let conn = db.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT host, id, severity, score, resolved_by, resolved_at, note, record              FROM incidents WHERE resolved = 1 ORDER BY resolved_at DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([limit as i64], |r| {
            let record: String = r.get(7)?;
            let v: serde_json::Value =
                serde_json::from_str(&record).unwrap_or(serde_json::Value::Null);
            Ok(AuditEntry {
                host: r.get(0)?,
                id: r.get::<_, i64>(1)? as u64,
                severity: r.get(2)?,
                score: r.get::<_, i64>(3)? as u32,
                resolved_by: r.get(4)?,
                resolved_at: r.get::<_, i64>(5)? as u64,
                note: r.get(6)?,
                subject: subject_comm(&v),
            })
        });
        match rows {
            Ok(it) => it.flatten().collect(),
            Err(_) => Vec::new(),
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
    fn sqlite_persists_and_audits_across_restart() {
        let dir = std::env::temp_dir().join(format!("ks-db-{}.sqlite", std::process::id()));
        let path = dir.to_str().unwrap();
        let _ = std::fs::remove_file(path);

        // First server life: ingest + resolve one.
        {
            let s = Store::persistent(path, 0).unwrap();
            s.ingest(
                "h1",
                "6.8",
                "10.0.0.1",
                json!({"severity":"CRITICAL","score":100,"subject":{"comm":"chmod"}}),
            );
            s.ingest(
                "h1",
                "6.8",
                "10.0.0.1",
                json!({"severity":"LOW","score":40,"subject":{"comm":"id"}}),
            );
            assert!(s.resolve("h1", 1, "alice", "sanctioned"));
            assert_eq!(
                s.fleet()[0].score,
                40,
                "score drops to unresolved after resolve"
            );
            let audit = s.audit(10);
            assert_eq!(audit.len(), 1);
            assert_eq!(audit[0].resolved_by, "alice");
            assert_eq!(audit[0].note, "sanctioned");
        }
        // Restart: reload from sqlite -- resolution + score survive.
        {
            let s = Store::persistent(path, 0).unwrap();
            assert_eq!(s.fleet()[0].score, 40, "resolution must survive restart");
            assert_eq!(s.audit(10).len(), 1, "audit trail must survive restart");
            // next id continues past the loaded max.
            s.ingest("h1", "", "", json!({"severity":"MEDIUM","score":55}));
            assert_eq!(s.fleet()[0].score, 55);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn band_matches_engine() {
        assert_eq!(band(0), "OK");
        assert_eq!(band(40), "LOW");
        assert_eq!(band(50), "MEDIUM");
        assert_eq!(band(100), "CRITICAL");
    }
}
