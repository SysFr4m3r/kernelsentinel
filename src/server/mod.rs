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
mod ship;
mod store;

pub use keys::{AgentKeys, generate_key};
pub use ship::{hostname, ship};
pub use store::{Store, band};

use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tiny_http::{Header, Method, Request, Response, Server};

pub struct Config {
    pub addr: String,
    /// Admin dashboard password. Required.
    pub admin_password: String,
    /// Shared fallback key (used only when no per-agent keys file is set).
    pub ingest_key: String,
    /// Per-agent keys (key -> host). When set, the key determines the host and
    /// the shared key is not accepted -- a leaked key cannot impersonate others.
    pub agent_keys: Option<AgentKeys>,
    /// NDJSON journal path for persistence. None = in-memory only.
    pub journal: Option<String>,
    /// TLS material. When set, the server speaks HTTPS.
    pub tls: Option<Tls>,
}

pub struct Tls {
    /// Path to the PEM certificate chain.
    pub cert: String,
    /// Path to the PEM private key.
    pub key: String,
}

struct Sessions {
    /// token -> expiry instant.
    live: Mutex<Vec<(String, Instant)>>,
}

impl Sessions {
    fn new() -> Self {
        Self {
            live: Mutex::new(Vec::new()),
        }
    }
    fn issue(&self) -> String {
        let token = random_token();
        let mut live = self.live.lock().unwrap();
        live.push((
            token.clone(),
            Instant::now() + Duration::from_secs(8 * 3600),
        ));
        token
    }
    fn valid(&self, token: &str) -> bool {
        let mut live = self.live.lock().unwrap();
        let now = Instant::now();
        live.retain(|(_, exp)| *exp > now);
        live.iter().any(|(t, _)| ct_eq(t, token))
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
            let s = Store::persistent(path).context("opening the incident journal")?;
            eprintln!("kernelsentinel: persisting incidents to {path}");
            s
        }
        None => Store::new(),
    });
    if let Some(k) = &cfg.agent_keys {
        eprintln!("kernelsentinel: {} per-agent key(s) loaded", k.len());
    }
    let sessions = Arc::new(Sessions::new());
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
        let (cfg, store, sessions) = (cfg.clone(), store.clone(), sessions.clone());
        // Each request is handled to completion (respond consumes it). A panic
        // in one handler must not take the server down.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle(req, &cfg, &store, &sessions)
        }));
        if outcome.is_err() {
            eprintln!("kernelsentinel: recovered from a panic handling a request");
        }
    }
    Ok(())
}

fn handle(mut req: Request, cfg: &Config, store: &Store, sessions: &Sessions) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    let resp: Response<std::io::Cursor<Vec<u8>>> = match (&method, path.as_str()) {
        // Agent -> server. Key-authenticated, one way in.
        (Method::Post, "/api/ingest") => {
            let presented = header(&req, "X-Sentinel-Key").unwrap_or_default();
            // With per-agent keys the KEY determines the host -- a self-declared
            // header is ignored, so a leaked key can only write its own bucket.
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
            let mut n = 0;
            for line in body.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                    store.ingest(&host, &kernel, &ip, v);
                    n += 1;
                }
            }
            text(200, &format!("accepted {n}"))
        }

        // Admin login -> session cookie.
        (Method::Post, "/api/login") => {
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).ok();
            let pw = form_field(&body, "password").unwrap_or_default();
            if !pw.is_empty() && ct_eq(&pw, &cfg.admin_password) {
                let token = sessions.issue();
                let mut r = text(200, "ok");
                r.add_header(
                    Header::from_bytes(
                        &b"Set-Cookie"[..],
                        format!("ks_session={token}; HttpOnly; SameSite=Strict; Path=/").as_bytes(),
                    )
                    .unwrap(),
                );
                r
            } else {
                text(401, "invalid credentials")
            }
        }

        // Everything below requires an admin session.
        (Method::Get, "/api/fleet") => {
            if authed(&req, sessions) {
                json(200, &store.fleet())
            } else {
                text(401, "auth required")
            }
        }
        (Method::Get, p) if p.starts_with("/api/host/") => {
            if !authed(&req, sessions) {
                text(401, "auth required")
            } else {
                let host = p.trim_start_matches("/api/host/");
                match store.host_incidents(host) {
                    Some(incs) => json(200, &incs),
                    None => text(404, "no such host"),
                }
            }
        }

        // Dashboard (a client-side gate swaps to login when the session is absent).
        (Method::Get, "/") | (Method::Get, "/index.html") => html(200, dashboard::PAGE),
        _ => text(404, "not found"),
    };
    let _ = req.respond(resp);
}

fn authed(req: &Request, sessions: &Sessions) -> bool {
    cookie(req, "ks_session").is_some_and(|t| sessions.valid(&t))
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
fn json<T: serde::Serialize>(code: u16, v: &T) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let mut r = Response::from_string(body).with_status_code(code);
    r.add_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap());
    r
}

#[cfg(test)]
mod tests {
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
