//! Central fleet store. Holds each reporting host's incidents and derives a
//! per-host risk score. In-memory and bounded for this first increment;
//! persistence (sqlite/file) is future work.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rusqlite::Connection;
use serde::Serialize;

use crate::heartbeat::{self, HeartbeatRecord};

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
    pub first_seen: u64,
    /// Server receive time of the last heartbeat. Zero means this agent has
    /// never sent one -- which is *not* the same as being dead, see `status`.
    pub last_heartbeat: u64,
    pub agent_version: String,
    pub uptime_secs: u64,
    pub events: u64,
    pub drops: u64,
    pub decode_panics: u64,
}

/// How long after its last heartbeat an agent stops counting as live. Three
/// missed reports rather than one, so a slow network or a busy host does not
/// flap the fleet view.
pub const STALE_AFTER_SECS: u64 = heartbeat::INTERVAL_SECS * 3;
/// ...and when it should be treated as gone rather than late.
pub const SILENT_AFTER_SECS: u64 = heartbeat::INTERVAL_SECS * 10;

/// Liveness of an agent, derived at read time rather than stored.
///
/// Derived, because a stored status would need a server-side timer to keep it
/// true and would be wrong in the window between ticks. The cost is that
/// "silent" is not an auditable event; the benefit is that it can never be
/// stale, which for a liveness signal is the property that matters.
pub fn agent_status(state: &HostState, now: u64) -> &'static str {
    if state.last_heartbeat == 0 {
        // Shipping incidents but never a heartbeat: an older agent, or one
        // whose stream carries only incidents. Claiming it is dead would be a
        // lie, so say what we actually know.
        return "unknown";
    }
    match now.saturating_sub(state.last_heartbeat) {
        d if d <= STALE_AFTER_SECS => "live",
        d if d <= SILENT_AFTER_SECS => "stale",
        _ => "silent",
    }
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
    /// "live" | "stale" | "silent" | "unknown" -- agent liveness, deliberately
    /// separate from `score`. A dead agent and a compromised host are different
    /// problems and collapsing them into one number would hide both.
    pub status: &'static str,
    pub last_heartbeat: u64,
    pub agent_version: String,
    pub uptime_secs: u64,
    pub events: u64,
    /// Ring-buffer drops. Non-zero means this host lost events, i.e. missed
    /// detections -- the panel must not present it as fully covered.
    pub drops: u64,
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

    pub fn has_db(&self) -> bool {
        self.db.is_some()
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
             CREATE INDEX IF NOT EXISTS idx_resolved ON incidents(resolved, resolved_at);
             CREATE TABLE IF NOT EXISTS users (
                 username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL,
                 role TEXT NOT NULL DEFAULT 'admin', created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS hosts (
                 host TEXT PRIMARY KEY,
                 first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                 last_heartbeat INTEGER NOT NULL DEFAULT 0,
                 kernel TEXT DEFAULT '', ip TEXT DEFAULT '',
                 agent_version TEXT DEFAULT '',
                 uptime_secs INTEGER DEFAULT 0,
                 events INTEGER DEFAULT 0, drops INTEGER DEFAULT 0,
                 decode_panics INTEGER DEFAULT 0
             );",
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

        // Restore agent liveness too. Without this a restart would erase every
        // clean host (they have no incidents to rebuild them from) and reset
        // their telemetry to zero.
        {
            let mut stmt = conn.prepare(
                "SELECT host, first_seen, last_seen, last_heartbeat, kernel, ip,
                        agent_version, uptime_secs, events, drops, decode_panics FROM hosts",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)? as u64,
                    r.get::<_, i64>(8)? as u64,
                    r.get::<_, i64>(9)? as u64,
                    r.get::<_, i64>(10)? as u64,
                ))
            })?;
            let mut hosts = store.hosts.lock().unwrap();
            for row in rows.flatten() {
                let (host, first, last, hb, kernel, ip, ver, up, ev, dr, dp) = row;
                let state = hosts.entry(host).or_default();
                state.first_seen = first;
                state.last_seen = state.last_seen.max(last);
                state.last_heartbeat = hb;
                if !kernel.is_empty() {
                    state.kernel = kernel;
                }
                if !ip.is_empty() {
                    state.ip = ip;
                }
                state.agent_version = ver;
                state.uptime_secs = up;
                state.events = ev;
                state.drops = dr;
                state.decode_panics = dp;
            }
        }

        let mut store = store;
        store.db = Some(Mutex::new(conn));
        Ok(store)
    }

    /// Record an agent check-in. Also the only path that makes a host with no
    /// incidents visible at all -- before this, a clean host was indistinguishable
    /// from one that had never existed.
    pub fn heartbeat(&self, host: &str, kernel: &str, ip: &str, hb: &HeartbeatRecord) {
        let now = epoch();
        let mut hosts = self.hosts.lock().unwrap();
        let state = hosts.entry(host.to_string()).or_default();
        if state.first_seen == 0 {
            state.first_seen = now;
        }
        state.last_seen = state.last_seen.max(now);
        state.last_heartbeat = now;
        state.agent_version = hb.agent_version.clone();
        state.uptime_secs = hb.uptime_secs;
        state.events = hb.events;
        state.drops = hb.drops;
        state.decode_panics = hb.decode_panics;
        if !kernel.is_empty() {
            state.kernel = kernel.to_string();
        }
        if !ip.is_empty() {
            state.ip = ip.to_string();
        }
        let (first_seen, kernel, ip) = (state.first_seen, state.kernel.clone(), state.ip.clone());
        drop(hosts);

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute(
                "INSERT INTO hosts (host, first_seen, last_seen, last_heartbeat, kernel, ip,
                                    agent_version, uptime_secs, events, drops, decode_panics)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(host) DO UPDATE SET
                   last_seen=excluded.last_seen, last_heartbeat=excluded.last_heartbeat,
                   kernel=excluded.kernel, ip=excluded.ip,
                   agent_version=excluded.agent_version, uptime_secs=excluded.uptime_secs,
                   events=excluded.events, drops=excluded.drops,
                   decode_panics=excluded.decode_panics",
                rusqlite::params![
                    host,
                    first_seen as i64,
                    now as i64,
                    now as i64,
                    kernel,
                    ip,
                    hb.agent_version,
                    hb.uptime_secs as i64,
                    hb.events as i64,
                    hb.drops as i64,
                    hb.decode_panics as i64,
                ],
            );
        }
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

    /// The HMAC secret for signing session tokens: read from the config table,
    /// generated and stored on first use, so tokens survive a restart. Without a
    /// database (in-memory mode) a fresh secret is returned each start.
    pub fn session_secret(&self) -> Vec<u8> {
        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            if let Ok(v) = conn.query_row("SELECT value FROM config WHERE key='secret'", [], |r| {
                r.get::<_, String>(0)
            }) {
                if let Some(b) = unhex(&v) {
                    return b;
                }
            }
            let secret = random_bytes(32);
            let _ = conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('secret', ?1)",
                [hex(&secret)],
            );
            return secret;
        }
        random_bytes(32)
    }

    /// Are there any user accounts? (used to seed the first admin)
    pub fn has_users(&self) -> bool {
        let Some(db) = &self.db else { return false };
        let conn = db.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    /// Verify a username/password; returns the role on success. Runs argon2
    /// even for an unknown user (against a dummy hash) so a missing account and
    /// a wrong password take the same time.
    pub fn verify_user(&self, username: &str, password: &str) -> Option<String> {
        let Some(db) = &self.db else { return None };
        let conn = db.lock().unwrap();
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT pw_hash, role FROM users WHERE username = ?1",
                [username],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .ok();
        match row {
            Some((hash, role)) if verify_pw(password, &hash) => Some(role),
            Some(_) => None,
            None => {
                // Dummy verify against a real hash to equalize timing (so a
                // missing user is not distinguishable from a wrong password).
                let _ = verify_pw(password, dummy_hash());
                None
            }
        }
    }

    /// Create a user. Fails if the database is absent or the name is taken.
    pub fn create_user(&self, username: &str, password: &str, role: &str) -> Result<(), String> {
        if username.is_empty() || password.len() < 8 {
            return Err("username required and password must be >= 8 chars".into());
        }
        let role = if role == "viewer" { "viewer" } else { "admin" };
        let Some(db) = &self.db else {
            return Err("user accounts require --journal (a database)".into());
        };
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (username, pw_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![username, hash_pw(password), role, epoch() as i64],
        )
        .map(|_| ())
        .map_err(|e| format!("could not create user (name taken?): {e}"))
    }

    pub fn list_users(&self) -> Vec<(String, String)> {
        let Some(db) = &self.db else {
            return Vec::new();
        };
        let conn = db.lock().unwrap();
        let mut stmt = match conn.prepare("SELECT username, role FROM users ORDER BY username") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)));
        rows.map(|it| it.flatten().collect()).unwrap_or_default()
    }

    /// Delete a user unless it is the last remaining admin (never lock yourself
    /// out).
    pub fn delete_user(&self, username: &str) -> Result<(), String> {
        let Some(db) = &self.db else {
            return Err("no database".into());
        };
        let conn = db.lock().unwrap();
        let admins: i64 = conn
            .query_row("SELECT COUNT(*) FROM users WHERE role='admin'", [], |r| {
                r.get(0)
            })
            .unwrap_or(0);
        let is_admin: bool = conn
            .query_row(
                "SELECT role FROM users WHERE username=?1",
                [username],
                |r| r.get::<_, String>(0),
            )
            .map(|role| role == "admin")
            .unwrap_or(false);
        if is_admin && admins <= 1 {
            return Err("cannot delete the last admin".into());
        }
        conn.execute("DELETE FROM users WHERE username=?1", [username])
            .map(|_| ())
            .map_err(|e| format!("{e}"))
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
        let now = epoch();
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
                    status: agent_status(state, now),
                    last_heartbeat: state.last_heartbeat,
                    agent_version: state.agent_version.clone(),
                    uptime_secs: state.uptime_secs,
                    events: state.events,
                    drops: state.drops,
                }
            })
            .collect();
        // Worst first by score; at equal score a host whose agent has gone
        // quiet outranks a healthy one, because "no findings" from an agent
        // that is not reporting is not the same reassurance as "no findings"
        // from one that is.
        let dark = |s: &str| matches!(s, "silent" | "stale");
        out.sort_by(|a, b| {
            b.score
                .cmp(&a.score)
                .then_with(|| dark(b.status).cmp(&dark(a.status)))
                .then_with(|| a.host.cmp(&b.host))
        });
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

/// A real argon2 hash computed once, for constant-time dummy verifies.
fn dummy_hash() -> &'static str {
    use std::sync::OnceLock;
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_pw("not-a-real-password-placeholder"))
}

fn hash_pw(pw: &str) -> String {
    // 16 random salt bytes from the OS CSPRNG, encoded for argon2.
    let salt = SaltString::encode_b64(&random_bytes(16)).expect("valid salt");
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

fn verify_pw(pw: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

    /// An agent that has never sent a heartbeat is *unknown*, never *silent*.
    /// Reporting an older agent as dead would be a false alarm in exactly the
    /// place operators must be able to trust the panel.
    #[test]
    fn agent_without_heartbeat_is_unknown_not_silent() {
        let state = HostState {
            last_heartbeat: 0,
            last_seen: 1_000,
            ..Default::default()
        };
        assert_eq!(agent_status(&state, 999_999), "unknown");
    }

    /// At equal score, a host that stopped reporting must sort above a healthy
    /// one -- otherwise the thing most worth looking at hides below the calm.
    #[test]
    fn silent_hosts_outrank_healthy_ones_at_equal_score() {
        let store = Store::new();
        store.heartbeat("aaa-healthy", "", "", &HeartbeatRecord::new(60, 10, 0, 0));
        store.heartbeat("zzz-silent", "", "", &HeartbeatRecord::new(60, 10, 0, 0));
        // Age zzz-silent past the silence threshold.
        {
            let mut hosts = store.hosts.lock().unwrap();
            let st = hosts.get_mut("zzz-silent").unwrap();
            st.last_heartbeat = epoch().saturating_sub(SILENT_AFTER_SECS + 60);
        }
        let fleet = store.fleet();
        assert_eq!(fleet[0].host, "zzz-silent", "silent host must sort first");
        assert_eq!(fleet[0].status, "silent");
        assert_eq!(fleet[1].host, "aaa-healthy");
    }

    #[test]
    fn agent_liveness_bands() {
        let at = |hb: u64, now: u64| {
            let state = HostState {
                last_heartbeat: hb,
                ..Default::default()
            };
            agent_status(&state, now)
        };
        let t = 1_000_000u64;
        assert_eq!(at(t, t), "live", "just reported");
        assert_eq!(
            at(t, t + STALE_AFTER_SECS),
            "live",
            "boundary is still live"
        );
        assert_eq!(at(t, t + STALE_AFTER_SECS + 1), "stale");
        assert_eq!(
            at(t, t + SILENT_AFTER_SECS),
            "stale",
            "boundary is still stale"
        );
        assert_eq!(at(t, t + SILENT_AFTER_SECS + 1), "silent");
    }

    /// A host that only ever sends heartbeats must still appear in the fleet --
    /// this is the whole point: silence used to be indistinguishable from a
    /// host that never existed.
    #[test]
    fn clean_host_is_visible_from_heartbeat_alone() {
        let store = Store::new();
        let hb = HeartbeatRecord::new(120, 5_000, 0, 0);
        store.heartbeat("clean-01", "6.19", "10.0.0.9", &hb);

        let fleet = store.fleet();
        assert_eq!(fleet.len(), 1, "a heartbeat alone must register the host");
        let h = &fleet[0];
        assert_eq!(h.host, "clean-01");
        assert_eq!(h.score, 0);
        assert_eq!(h.n, 0, "no incidents");
        assert_eq!(h.status, "live");
        assert_eq!(h.events, 5_000);
        assert_eq!(h.kernel, "6.19");
    }

    /// Drops are missed detections and must reach the panel; they were counted
    /// in BPF and read by nothing before this.
    #[test]
    fn drops_are_reported_to_the_fleet() {
        let store = Store::new();
        store.heartbeat(
            "busy-01",
            "",
            "",
            &HeartbeatRecord::new(60, 900_000, 1_743, 2),
        );
        let h = &store.fleet()[0];
        assert_eq!(h.drops, 1_743);
    }

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
