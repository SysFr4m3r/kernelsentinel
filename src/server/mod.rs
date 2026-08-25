//! The central fleet server. Linux agents POST their incidents here
//! (API-key authenticated); admins log in to a read-only, session-authenticated
//! dashboard that ranks hosts by score.
//!
//! Security posture, by construction:
//!   - data flows ONE WAY: host -> server. There is no route back to a host, so
//!     the dashboard can view and audit but never reach into a monitored box.
//!   - the ingest endpoint requires a shared key; the dashboard/API require an
//!     admin session. Both checks are constant-time and fail closed.
//!   - bind to a loopback/explicit address; put TLS in front for real deployment.

mod dashboard;
mod keys;
mod session;
mod ship;
mod store;

pub use keys::{AgentKeys, generate_key};
pub use ship::{hostname, ship};
pub use store::{Store, band};

use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use anyhow::{Context, Result};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::heartbeat::HeartbeatRecord;
use crate::notify;

pub struct Config {
    pub addr: String,
    /// Admin dashboard password. Required.
    pub admin_password: String,
    /// Shared fallback key (used only when no per-agent keys file is set).
    pub ingest_key: String,
    /// Per-agent keys (key -> host). When set, the key determines the host and
    /// the shared key is not accepted -- a leaked key cannot impersonate others.
    pub agent_keys: Option<AgentKeys>,
    /// sqlite database path for persistence. None = in-memory only.
    pub journal: Option<String>,
    /// Prune incidents older than this many days on startup (0 = keep forever).
    pub retain_days: u64,
    /// TLS material. When set, the server speaks HTTPS.
    pub tls: Option<Tls>,
    /// Outbound alert sinks. Configured from the command line only -- a URL the
    /// server fetches is an SSRF primitive, so it stays out of the web UI.
    pub alerts: Vec<notify::Sink>,
    /// Lowest severity worth delivering.
    pub alert_min_severity: String,
    /// Cap on alerts delivered per minute (0 = no cap).
    pub alert_max_per_min: u32,
}

pub struct Tls {
    /// Path to the PEM certificate chain.
    pub cert: String,
    /// Path to the PEM private key.
    pub key: String,
}

/// Fan-out of "something changed" notifications to every connected dashboard's
/// SSE stream. Each subscriber gets a channel; publish sends to all, dropping
/// any whose receiver has gone (the dashboard disconnected).
#[derive(Default)]
struct Broadcaster {
    clients: Mutex<Vec<(u64, Sender<String>)>>,
    next_id: AtomicU64,
}
impl Broadcaster {
    /// Subscribe, returning a guard that unregisters on drop.
    ///
    /// `publish` prunes dead senders, but a fleet with nothing to say never
    /// publishes -- and that is exactly the case where someone leaves the
    /// dashboard open: every agent down, nothing arriving. Each 25s poll cycle
    /// would then add a sender that nothing ever removed. Unregistering when
    /// the poll finishes bounds the list by the number of live pollers instead
    /// of by uptime.
    fn subscribe(self: &Arc<Self>) -> Subscription {
        let (tx, rx) = channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.clients.lock().unwrap().push((id, tx));
        Subscription {
            bus: self.clone(),
            id,
            rx,
        }
    }
    fn publish(&self, msg: String) {
        self.clients
            .lock()
            .unwrap()
            .retain(|(_, tx)| tx.send(msg.clone()).is_ok());
    }
    fn unsubscribe(&self, id: u64) {
        self.clients.lock().unwrap().retain(|(i, _)| *i != id);
    }
    #[cfg(test)]
    fn len(&self) -> usize {
        self.clients.lock().unwrap().len()
    }
}

/// Holds a subscription open for as long as it is alive. Drop runs on the
/// normal path and on unwind, so a panicking poll handler cannot leak an entry.
struct Subscription {
    bus: Arc<Broadcaster>,
    id: u64,
    rx: Receiver<String>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.bus.unsubscribe(self.id);
    }
}

pub fn serve(cfg: Config) -> Result<()> {
    if cfg.admin_password.is_empty() {
        anyhow::bail!("refusing to start without an admin password (set KS_ADMIN_PASSWORD)");
    }
    if cfg.agent_keys.is_none() && cfg.ingest_key.is_empty() {
        anyhow::bail!(
            "refusing to start without agent authentication: set --keys <file> \
             (per-agent keys, recommended) or KS_INGEST_KEY (single shared key)"
        );
    }
    let store = Arc::new(match &cfg.journal {
        Some(path) => {
            let s = Store::persistent(path, cfg.retain_days)
                .map_err(|e| anyhow::anyhow!("opening sqlite database {path}: {e}"))?;
            eprintln!("kernelsentinel: persisting incidents to sqlite {path}");
            s
        }
        None => Store::new(),
    });
    if let Some(k) = &cfg.agent_keys {
        eprintln!("kernelsentinel: {} per-agent key(s) loaded", k.len());
    }

    // Session-signing secret (persisted, so logins survive a restart).
    let secret = Arc::new(store.session_secret());
    let bus = Arc::new(Broadcaster::default());

    // Seed the first admin from KS_ADMIN_PASSWORD if there are no users yet.
    if !store.has_users() && !cfg.admin_password.is_empty() {
        match store.create_user("admin", &cfg.admin_password, "admin") {
            Ok(()) => eprintln!("kernelsentinel: seeded admin user 'admin' from KS_ADMIN_PASSWORD"),
            Err(e) => eprintln!("kernelsentinel: could not seed admin: {e}"),
        }
    }
    if !store.has_db() {
        eprintln!(
            "kernelsentinel: NOTE -- without --journal, user accounts are unavailable;              falling back to the single KS_ADMIN_PASSWORD login (user 'admin')."
        );
    }
    // Alert delivery. Built before the listener so a misconfigured sink is
    // reported at startup rather than on the first incident.
    let mut cfg = cfg;
    let sinks = std::mem::take(&mut cfg.alerts);
    let notifier = if sinks.is_empty() {
        eprintln!(
            "kernelsentinel: NOTE -- no alert delivery configured; findings appear in the \
             dashboard only. See --alert-webhook / --alert-syslog."
        );
        None
    } else {
        eprintln!(
            "kernelsentinel: alerting at {} and above via {} sink(s), max {}/min",
            cfg.alert_min_severity,
            sinks.len(),
            cfg.alert_max_per_min
        );
        Some(Arc::new(notify::Notifier::spawn(
            sinks,
            &cfg.alert_min_severity,
            cfg.alert_max_per_min,
        )))
    };
    let cfg = Arc::new(cfg);

    let server = match &cfg.tls {
        Some(tls) => {
            let certificate = std::fs::read(&tls.cert)
                .with_context(|| format!("reading TLS cert {}", tls.cert))?;
            let private_key =
                std::fs::read(&tls.key).with_context(|| format!("reading TLS key {}", tls.key))?;
            let s = Server::https(
                &cfg.addr,
                tiny_http::SslConfig {
                    certificate,
                    private_key,
                },
            )
            .map_err(|e| anyhow::anyhow!("binding {} (https): {e}", cfg.addr))?;
            eprintln!("kernelsentinel: fleet server on https://{} (TLS)", cfg.addr);
            s
        }
        None => {
            let s = Server::http(&cfg.addr)
                .map_err(|e| anyhow::anyhow!("binding {}: {e}", cfg.addr))
                .context("starting HTTP server")?;
            eprintln!(
                "kernelsentinel: fleet server on http://{} (NO TLS)",
                cfg.addr
            );
            eprintln!(
                "kernelsentinel: WARNING -- no TLS. Use --tls-cert/--tls-key, or keep this on                  localhost only. The ingest key travels in a header."
            );
            s
        }
    };
    eprintln!("kernelsentinel: admin dashboard + agent ingest ready");

    for req in server.incoming_requests() {
        let (cfg, store, secret, bus) = (cfg.clone(), store.clone(), secret.clone(), bus.clone());
        let notifier = notifier.clone();
        // Each request is handled to completion (respond consumes it). A panic
        // in one handler must not take the server down.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle(req, &cfg, &store, &secret, &bus, notifier.as_deref())
        }));
        if outcome.is_err() {
            eprintln!("kernelsentinel: recovered from a panic handling a request");
        }
    }
    Ok(())
}

/// Flatten an incident record into the fields an alert needs. The subject's
/// command line is included deliberately: an alert that says only "a SUID binary
/// appeared" sends the responder back to the dashboard to find out what ran.
fn alert_from(host: &str, v: &serde_json::Value) -> notify::Alert {
    let subject = v
        .get("subject")
        .and_then(|s| s.get("comm"))
        .and_then(|c| c.as_str())
        .unwrap_or("incident")
        .to_string();
    let cmdline = v
        .get("subject")
        .and_then(|s| s.get("cmdline"))
        .and_then(|c| c.as_str())
        .unwrap_or_default()
        .to_string();
    let attack = v
        .get("attack")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    notify::Alert {
        host: host.to_string(),
        severity: v
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("INFO")
            .to_string(),
        score: v.get("score").and_then(|s| s.as_u64()).unwrap_or(0) as u32,
        subject,
        cmdline,
        attack,
    }
}

fn handle(
    mut req: Request,
    cfg: &Config,
    store: &Store,
    secret: &[u8],
    bus: &Arc<Broadcaster>,
    notifier: Option<&notify::Notifier>,
) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    let resp: Response<std::io::Cursor<Vec<u8>>> = match (&method, path.as_str()) {
        // Agent -> server. Key-authenticated, one way in.
        (Method::Post, "/api/ingest") => {
            let presented = header(&req, "X-Sentinel-Key").unwrap_or_default();
            let host = match &cfg.agent_keys {
                Some(keys) => match keys.resolve(&presented) {
                    Some(h) => h.to_string(),
                    None => {
                        let _ = req.respond(text(401, "unknown agent key"));
                        return;
                    }
                },
                None => {
                    if !ct_eq(&presented, &cfg.ingest_key) {
                        let _ = req.respond(text(401, "invalid ingest key"));
                        return;
                    }
                    header(&req, "X-Sentinel-Host").unwrap_or_else(|| "unknown".into())
                }
            };
            let kernel = header(&req, "X-Sentinel-Kernel").unwrap_or_default();
            let ip = header(&req, "X-Sentinel-Ip").unwrap_or_default();
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).ok();
            // One stream carries two record kinds; the schema tag tells them
            // apart. Heartbeats are far more frequent than incidents, so they
            // must not be stored as findings or the panel would drown in them.
            let (mut n, mut beats) = (0, 0);
            for line in body.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };
                if HeartbeatRecord::is_heartbeat(&v) {
                    if let Ok(hb) = serde_json::from_value::<HeartbeatRecord>(v) {
                        store.heartbeat(&host, &kernel, &ip, &hb);
                        beats += 1;
                    }
                } else {
                    // Push before storing is tempting (lower latency) but a
                    // delivery that outruns the write would point at a finding
                    // the dashboard cannot yet show.
                    store.ingest(&host, &kernel, &ip, v.clone());
                    if let Some(tx) = notifier {
                        tx.notify(alert_from(&host, &v));
                    }
                    n += 1;
                }
            }
            if n > 0 || beats > 0 {
                // Notify connected dashboards to refresh (host name only; the
                // dashboard re-fetches through the authenticated API). Heartbeats
                // publish too, so a host coming back to life updates at once.
                bus.publish(format!("{{\"host\":\"{host}\"}}"));
            }
            text(
                200,
                &format!("accepted {n} incident(s), {beats} heartbeat(s)"),
            )
        }

        // Admin login: username + password -> a signed session cookie.
        (Method::Post, "/api/login") => {
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).ok();
            let username = form_field(&body, "username").unwrap_or_default();
            let password = form_field(&body, "password").unwrap_or_default();
            // Back-compat: no accounts DB -> single admin from KS_ADMIN_PASSWORD.
            let role = if store.has_db() {
                store.verify_user(&username, &password)
            } else if !cfg.admin_password.is_empty()
                && username == "admin"
                && ct_eq(&password, &cfg.admin_password)
            {
                Some("admin".to_string())
            } else {
                None
            };
            match role {
                Some(role) => {
                    let token = session::issue(secret, &username, &role, 8 * 3600);
                    let mut r = text(200, "ok");
                    r.add_header(
                        Header::from_bytes(
                            &b"Set-Cookie"[..],
                            format!(
                                "ks_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
                                8 * 3600
                            )
                            .as_bytes(),
                        )
                        .unwrap(),
                    );
                    r
                }
                None => text(401, "invalid credentials"),
            }
        }
        (Method::Post, "/api/logout") => {
            let mut r = text(200, "ok");
            r.add_header(
                Header::from_bytes(
                    &b"Set-Cookie"[..],
                    &b"ks_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"[..],
                )
                .unwrap(),
            );
            r
        }

        // Who am I (drives the dashboard's admin-only UI).
        (Method::Get, "/api/me") => match session(&req, secret) {
            Some((username, role)) => json(
                200,
                &serde_json::json!({"username": username, "role": role}),
            ),
            None => text(401, "auth required"),
        },

        (Method::Get, "/api/fleet") => match session(&req, secret) {
            Some(_) => json(200, &store.fleet()),
            None => text(401, "auth required"),
        },
        // Cross-host activity: what happened anywhere, newest first. The
        // per-host view answers "how is web-01?"; this answers "what just
        // happened?", which is where an analyst actually starts.
        (Method::Get, "/api/incidents") => match session(&req, secret) {
            Some(_) => json(200, &store.recent_incidents(200)),
            None => text(401, "auth required"),
        },
        (Method::Get, "/api/audit") => match session(&req, secret) {
            Some(_) => json(200, &store.audit(200)),
            None => text(401, "auth required"),
        },
        (Method::Get, p) if p.starts_with("/api/host/") => match session(&req, secret) {
            None => text(401, "auth required"),
            Some(_) => {
                let host = p.trim_start_matches("/api/host/");
                match store.host_incidents(host) {
                    Some(incs) => json(200, &incs),
                    None => text(404, "no such host"),
                }
            }
        },
        // Resolve an incident -- records the actual signed-in username.
        (Method::Post, "/api/resolve") => match session(&req, secret) {
            None => text(401, "auth required"),
            Some((username, _)) => {
                let mut body = String::new();
                req.as_reader().read_to_string(&mut body).ok();
                let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("");
                let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("");
                if store.resolve(host, id, &username, note) {
                    text(200, "resolved")
                } else {
                    text(404, "no such incident")
                }
            }
        },

        // --- user management (admin only) ---
        (Method::Get, "/api/users") => match session(&req, secret) {
            Some((_, role)) if role == "admin" => {
                let users: Vec<_> = store
                    .list_users()
                    .into_iter()
                    .map(|(u, r)| serde_json::json!({"username": u, "role": r}))
                    .collect();
                json(200, &users)
            }
            _ => text(403, "admin only"),
        },
        (Method::Post, "/api/users") => match session(&req, secret) {
            Some((_, role)) if role == "admin" => {
                let mut body = String::new();
                req.as_reader().read_to_string(&mut body).ok();
                let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let u = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
                let p = v.get("password").and_then(|x| x.as_str()).unwrap_or("");
                let r = v.get("role").and_then(|x| x.as_str()).unwrap_or("admin");
                match store.create_user(u, p, r) {
                    Ok(()) => text(200, "created"),
                    Err(e) => text(400, &e),
                }
            }
            _ => text(403, "admin only"),
        },
        (Method::Post, "/api/users/delete") => match session(&req, secret) {
            Some((_, role)) if role == "admin" => {
                let mut body = String::new();
                req.as_reader().read_to_string(&mut body).ok();
                let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                let u = v.get("username").and_then(|x| x.as_str()).unwrap_or("");
                match store.delete_user(u) {
                    Ok(()) => text(200, "deleted"),
                    Err(e) => text(400, &e),
                }
            }
            _ => text(403, "admin only"),
        },

        // Long-poll: the dashboard holds a request open; the server answers the
        // instant an agent ships an incident (or after a timeout, so the client
        // re-polls). Handled in its own thread so the blocking wait does not
        // stall the single-threaded request loop. Near-real-time without SSE's
        // chunked-flush issues in tiny_http.
        (Method::Get, "/api/poll") => {
            if session(&req, secret).is_none() {
                let _ = req.respond(text(401, "auth required"));
                return;
            }
            let sub = bus.subscribe();
            std::thread::spawn(move || {
                let resp = match sub.rx.recv_timeout(Duration::from_secs(25)) {
                    Ok(msg) => json_str(200, &msg),
                    Err(_) => text(204, ""),
                };
                let _ = req.respond(resp);
            });
            return;
        }
        (Method::Get, "/") | (Method::Get, "/index.html") => html(200, dashboard::PAGE),
        _ => text(404, "not found"),
    };
    let _ = req.respond(resp);
}

/// Resolve the signed session cookie to (username, role), if valid.
fn session(req: &Request, secret: &[u8]) -> Option<(String, String)> {
    let token = cookie(req, "ks_session")?;
    session::validate(secret, &token)
}

// --- helpers ---

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
}

fn cookie(req: &Request, name: &str) -> Option<String> {
    let raw = header(req, "Cookie")?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

fn form_field(body: &str, key: &str) -> Option<String> {
    body.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| urldecode(v))
}

fn urldecode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(c) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(c as char);
                    i += 2;
                }
            }
            c => out.push(c as char),
        }
        i += 1;
    }
    out
}

/// Constant-time byte comparison, so a token/key/password check cannot be probed
/// by timing.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn random_token() -> String {
    // 32 bytes from the OS CSPRNG.
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn text(code: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body).with_status_code(code)
}
fn html(code: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut r = Response::from_string(body).with_status_code(code);
    r.add_header(
        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
    );
    r
}
fn json_str(code: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut r = Response::from_string(body).with_status_code(code);
    r.add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    r
}
fn json<T: serde::Serialize>(code: u16, v: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let mut r = Response::from_string(body).with_status_code(code);
    r.add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    r
}

#[cfg(test)]
mod tests {

    /// The failure this guards against: a fleet producing nothing never calls
    /// publish, so before the RAII guard each finished poll left its sender
    /// behind and the list grew with uptime rather than with viewers.
    #[test]
    fn finished_polls_do_not_accumulate() {
        let bus = Arc::new(Broadcaster::default());
        for _ in 0..500 {
            let sub = bus.subscribe();
            assert_eq!(bus.len(), 1, "one live poller at a time");
            drop(sub); // the poll responds and its thread ends
        }
        assert_eq!(bus.len(), 0, "no sender may outlive its poll");
    }

    #[test]
    fn concurrent_pollers_are_all_registered_and_all_released() {
        let bus = Arc::new(Broadcaster::default());
        let subs: Vec<_> = (0..8).map(|_| bus.subscribe()).collect();
        assert_eq!(bus.len(), 8);
        // A publish reaches every live poller.
        bus.publish("{\"host\":\"h\"}".to_string());
        for s in &subs {
            assert!(
                s.rx.try_recv().is_ok(),
                "every live poller must be notified"
            );
        }
        drop(subs);
        assert_eq!(bus.len(), 0);
    }

    /// Drop runs on unwind too, so a panicking handler cannot leak an entry.
    #[test]
    fn a_panicking_poll_still_unregisters() {
        let bus = Arc::new(Broadcaster::default());
        let b = bus.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _sub = b.subscribe();
            panic!("handler blew up");
        }));
        assert_eq!(bus.len(), 0, "unwind must still release the subscription");
    }

    use super::*;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq("hunter2", "hunter2"));
        assert!(!ct_eq("hunter2", "hunter3"));
        assert!(!ct_eq("short", "longerkey"));
    }

    #[test]
    fn urldecode_handles_encoding() {
        assert_eq!(urldecode("a%2Bb+c"), "a+b c");
        assert_eq!(
            form_field("password=p%40ss+word", "password").unwrap(),
            "p@ss word"
        );
    }

    #[test]
    fn random_tokens_differ() {
        assert_ne!(random_token(), random_token());
        assert_eq!(random_token().len(), 64);
    }
}
