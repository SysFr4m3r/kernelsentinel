//! Alert delivery.
//!
//! A finding that lands only in a dashboard is a finding nobody sees until
//! somebody thinks to look. This pushes incidents out to where people already
//! are: a chat webhook, or syslog for a SIEM.
//!
//! Delivery runs on its own thread behind a queue. The server's request loop is
//! single-threaded, so a slow or dead webhook must never be in the path of an
//! agent shipping an incident -- an alerting failure has to degrade to a logged
//! error, never to backpressure on ingest.
//!
//! Outbound only, and configured from the command line rather than the web UI:
//! a URL the server will fetch is an SSRF primitive, so it stays out of reach of
//! anything a dashboard session could touch.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use crate::http::{self, Tls};

/// Severity ordering, mirroring the engine's bands.
pub fn rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

pub fn parse_min_severity(s: &str) -> Option<String> {
    let up = s.to_ascii_uppercase();
    matches!(up.as_str(), "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL").then_some(up)
}

pub enum Sink {
    /// HTTP POST of a JSON body. Carries a Slack/Mattermost-compatible `text`
    /// field alongside structured fields so it works with a chat webhook out of
    /// the box without giving up machine-readable detail.
    Webhook {
        url: String,
        pinned: Option<Vec<u8>>,
    },
    /// A local syslog datagram socket, usually /dev/log.
    Syslog { socket: String },
}

pub struct Alert {
    pub host: String,
    pub severity: String,
    pub score: u32,
    pub subject: String,
    pub cmdline: String,
    pub attack: Vec<String>,
}

impl Alert {
    /// One line a human can act on: what, where, how bad, and the command.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} {}/100 on {} — {}",
            self.severity, self.score, self.host, self.subject
        );
        if !self.cmdline.is_empty() {
            s.push_str(&format!(": {}", self.cmdline));
        }
        if !self.attack.is_empty() {
            s.push_str(&format!(" [{}]", self.attack.join(", ")));
        }
        s
    }

    fn json(&self) -> String {
        serde_json::json!({
            "text": self.summary(),
            "source": "kernelsentinel",
            "host": self.host,
            "severity": self.severity,
            "score": self.score,
            "subject": self.subject,
            "cmdline": self.cmdline,
            "attack": self.attack,
        })
        .to_string()
    }

    /// RFC3164-ish priority: facility 4 (security/authorization) times 8 plus
    /// the severity level.
    fn syslog_priority(&self) -> u8 {
        let level = match self.severity.as_str() {
            "CRITICAL" => 2, // crit
            "HIGH" => 3,     // err
            "MEDIUM" => 4,   // warning
            _ => 5,          // notice
        };
        4 * 8 + level
    }
}

pub struct Notifier {
    tx: SyncSender<Alert>,
    min_rank: u8,
}

impl Notifier {
    /// Start the dispatcher. `max_per_min` caps delivery so an incident storm
    /// cannot turn into an alert storm; suppressed alerts are counted and
    /// reported rather than dropped silently.
    pub fn spawn(sinks: Vec<Sink>, min_severity: &str, max_per_min: u32) -> Self {
        // Bounded: if the queue fills, dropping the newest with a loud log is
        // better than growing memory without limit inside a security daemon.
        let (tx, rx) = sync_channel::<Alert>(1024);
        let min_rank = rank(min_severity);
        std::thread::spawn(move || dispatch(rx, sinks, max_per_min));
        Self { tx, min_rank }
    }

    /// Queue an alert. Never blocks and never fails the caller.
    pub fn notify(&self, alert: Alert) {
        if rank(&alert.severity) < self.min_rank {
            return;
        }
        match self.tx.try_send(alert) {
            Ok(()) => {}
            Err(TrySendError::Full(a)) => {
                eprintln!("kernelsentinel: alert queue full, dropped: {}", a.summary());
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

fn dispatch(rx: Receiver<Alert>, sinks: Vec<Sink>, max_per_min: u32) {
    let mut window_start = std::time::Instant::now();
    let mut in_window = 0u32;
    let mut suppressed = 0u32;

    for alert in rx {
        if window_start.elapsed() >= std::time::Duration::from_secs(60) {
            if suppressed > 0 {
                deliver_all(
                    &sinks,
                    &Alert {
                        host: "kernelsentinel".into(),
                        severity: "MEDIUM".into(),
                        score: 0,
                        subject: format!(
                            "{suppressed} further alert(s) suppressed by the rate limit"
                        ),
                        cmdline: String::new(),
                        attack: vec![],
                    },
                );
            }
            window_start = std::time::Instant::now();
            in_window = 0;
            suppressed = 0;
        }
        if max_per_min > 0 && in_window >= max_per_min {
            suppressed += 1;
            continue;
        }
        in_window += 1;
        deliver_all(&sinks, &alert);
    }
}

fn deliver_all(sinks: &[Sink], alert: &Alert) {
    for sink in sinks {
        if let Err(e) = deliver(sink, alert) {
            // An alerting failure must be visible but must not be fatal: the
            // monitoring itself keeps working.
            eprintln!("kernelsentinel: alert delivery failed: {e}");
        }
    }
}

fn deliver(sink: &Sink, alert: &Alert) -> anyhow::Result<()> {
    match sink {
        Sink::Webhook { url, pinned } => {
            let tls = match pinned {
                Some(der) => Tls::Pinned(der.clone()),
                None => Tls::SystemRoots,
            };
            let status = http::post(url, &[], "application/json", &alert.json(), tls)?;
            if !http::is_ok(&status) {
                anyhow::bail!("webhook {url} returned {status}");
            }
            Ok(())
        }
        Sink::Syslog { socket } => {
            use std::os::unix::net::UnixDatagram;
            let sock = UnixDatagram::unbound()?;
            let msg = format!(
                "<{}>kernelsentinel: {}",
                alert.syslog_priority(),
                alert.summary()
            );
            sock.send_to(msg.as_bytes(), socket)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(sev: &str) -> Alert {
        Alert {
            host: "web-01".into(),
            severity: sev.into(),
            score: 100,
            subject: "chmod".into(),
            cmdline: "chmod u+s /tmp/.x".into(),
            attack: vec!["T1068".into(), "T1548.001".into()],
        }
    }

    #[test]
    fn summary_names_what_where_and_the_command() {
        let s = alert("CRITICAL").summary();
        assert!(s.contains("CRITICAL"));
        assert!(s.contains("web-01"), "must name the host");
        assert!(s.contains("chmod u+s /tmp/.x"), "must carry the command");
        assert!(s.contains("T1548.001"));
    }

    #[test]
    fn severity_ordering_is_total_and_matches_the_engine() {
        assert!(rank("CRITICAL") > rank("HIGH"));
        assert!(rank("HIGH") > rank("MEDIUM"));
        assert!(rank("MEDIUM") > rank("LOW"));
        assert!(rank("LOW") > rank("INFO"));
        assert_eq!(rank("nonsense"), 0);
    }

    #[test]
    fn min_severity_parsing_rejects_junk() {
        assert_eq!(parse_min_severity("high").as_deref(), Some("HIGH"));
        assert_eq!(parse_min_severity("CRITICAL").as_deref(), Some("CRITICAL"));
        assert!(parse_min_severity("urgent").is_none());
    }

    /// A webhook body must be valid JSON and carry both the human `text` field
    /// chat tools read and the structured fields a pipeline reads.
    #[test]
    fn webhook_body_is_valid_json_with_both_shapes() {
        let v: serde_json::Value = serde_json::from_str(&alert("HIGH").json()).unwrap();
        assert!(v["text"].as_str().unwrap().contains("web-01"));
        assert_eq!(v["severity"], "HIGH");
        assert_eq!(v["score"], 100);
        assert_eq!(v["host"], "web-01");
        assert_eq!(v["attack"][1], "T1548.001");
    }

    #[test]
    fn syslog_priority_maps_severity_to_level() {
        // facility 4 (security) * 8 + level
        assert_eq!(alert("CRITICAL").syslog_priority(), 34);
        assert_eq!(alert("HIGH").syslog_priority(), 35);
        assert_eq!(alert("MEDIUM").syslog_priority(), 36);
        assert_eq!(alert("LOW").syslog_priority(), 37);
    }
}
