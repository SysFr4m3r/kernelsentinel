//! Agent shipping: read incident NDJSON (from `run --json` or `replay --json`)
//! and POST it to a central fleet server. This is the host->central direction --
//! the only direction. There is deliberately no client that accepts commands
//! from the server.
//!
//! Speaks http:// (localhost/dev) or https:// with a pinned server certificate
//! (--ca). The ingest key travels in a header, so use https for anything beyond
//! localhost.

use std::io::BufRead;

use anyhow::Result;

use crate::http::{self, Tls};

/// Read NDJSON incidents from `reader` and POST each batch to `url`
/// (`http://host:port`). `key` authenticates the agent; `host` labels it.
pub fn ship(
    url: &str,
    key: &str,
    host: &str,
    ca: Option<&str>,
    reader: impl BufRead,
) -> Result<()> {
    let kernel = read_first_line("/proc/sys/kernel/osrelease");
    // Resolved once up front: re-reading per batch would be wasted work, and a
    // cert file that vanishes mid-run must not silently downgrade trust.
    let pinned = match ca {
        Some(path) => Some(http::load_pinned_cert(path)?),
        None => None,
    };

    let mut sent = 0u64;
    let mut beats = 0u64;
    let mut batch = String::new();
    let flush = |batch: &mut String| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        post(url, key, host, &kernel, pinned.as_deref(), batch)?;
        batch.clear();
        Ok(())
    };

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // Heartbeats share the stream with incidents; count them apart so the
        // summary does not report an idle agent as having found something.
        if line.contains(crate::heartbeat::SCHEMA) {
            beats += 1;
        } else {
            sent += 1;
        }
        batch.push_str(&line);
        batch.push('\n');
        // Flush per incident: incidents are infrequent, so ship each promptly
        // rather than buffering (a live `run --json | ship` must not sit silent).
        flush(&mut batch)?;
    }
    flush(&mut batch)?;
    eprintln!("kernelsentinel: shipped {sent} incident(s), {beats} heartbeat(s) to {url}");
    Ok(())
}

/// Adds the agent identity headers on top of the shared HTTP client.
///
/// The fleet server's identity is its *certificate*, not a public CA: an agent
/// must not accept some other host that merely holds a valid cert, so there is
/// no system-root fallback here.
fn post(
    url: &str,
    key: &str,
    host: &str,
    kernel: &str,
    pinned: Option<&[u8]>,
    body: &str,
) -> Result<()> {
    let tls = match pinned {
        Some(der) => Tls::Pinned(der.to_vec()),
        // Unused for http://, but an https URL without a pin has no trust
        // anchor at all and must not proceed.
        None if url.starts_with("https://") => {
            anyhow::bail!("https requires --ca <server-cert.pem> to pin the server")
        }
        None => Tls::Pinned(Vec::new()),
    };
    let headers = [
        ("X-Sentinel-Key", key.to_string()),
        ("X-Sentinel-Host", host.to_string()),
        ("X-Sentinel-Kernel", kernel.to_string()),
    ];
    let status = http::post(url, &headers, "application/x-ndjson", body, tls)?;
    if !http::is_ok(&status) {
        anyhow::bail!("server rejected the batch: {status}");
    }
    Ok(())
}

fn read_first_line(path: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_default()
}

/// The local hostname, for labeling shipped incidents.
pub fn hostname() -> String {
    read_first_line("/proc/sys/kernel/hostname")
        .split('\n')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An https target with no pinned certificate must fail closed rather than
    /// fall back to any weaker trust.
    #[test]
    fn https_without_a_pin_is_refused() {
        let err = post("https://central/api/ingest", "k", "h", "6.19", None, "{}")
            .expect_err("https with no pin must not proceed");
        assert!(err.to_string().contains("--ca"), "got: {err}");
    }
}
