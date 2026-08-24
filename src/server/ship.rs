//! Agent shipping: read incident NDJSON (from `run --json` or `replay --json`)
//! and POST it to a central fleet server. This is the host->central direction --
//! the only direction. There is deliberately no client that accepts commands
//! from the server.
//!
//! v1 speaks plain HTTP for a localhost demo; a real deployment MUST wrap this
//! in TLS (a reverse proxy, or a TLS client). The ingest key travels in a
//! header, so without TLS it is only as private as the network path.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;

use anyhow::{Context, Result};

/// Read NDJSON incidents from `reader` and POST each batch to `url`
/// (`http://host:port`). `key` authenticates the agent; `host` labels it.
pub fn ship(url: &str, key: &str, host: &str, reader: impl BufRead) -> Result<()> {
    let (hostport, path) = split_url(url)?;
    let kernel = read_first_line("/proc/sys/kernel/osrelease");

    let mut sent = 0u64;
    let mut batch = String::new();
    let flush = |batch: &mut String| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        post(&hostport, &path, key, host, &kernel, batch)?;
        batch.clear();
        Ok(())
    };

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        batch.push_str(&line);
        batch.push('\n');
        sent += 1;
        // Ship in small batches so a live stream shows up promptly.
        if batch.len() > 16 * 1024 {
            flush(&mut batch)?;
        }
    }
    flush(&mut batch)?;
    eprintln!("kernelsentinel: shipped {sent} incident(s) to {url}");
    Ok(())
}

fn post(hostport: &str, path: &str, key: &str, host: &str, kernel: &str, body: &str) -> Result<()> {
    let mut stream =
        TcpStream::connect(hostport).with_context(|| format!("connecting to {hostport}"))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nX-Sentinel-Key: {key}\r\n\
         X-Sentinel-Host: {host}\r\nX-Sentinel-Kernel: {kernel}\r\n\
         Content-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .context("sending request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok();
    let status = resp.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        anyhow::bail!("server rejected the batch: {status}");
    }
    Ok(())
}

fn split_url(url: &str) -> Result<(String, String)> {
    let rest = url
        .strip_prefix("http://")
        .context("ship URL must start with http:// (v1 is plain HTTP; front with TLS)")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/api/ingest".to_string()),
    };
    let hostport = if hostport.contains(':') {
        hostport
    } else {
        format!("{hostport}:80")
    };
    Ok((hostport, path))
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

    #[test]
    fn url_splitting() {
        assert_eq!(
            split_url("http://10.0.0.5:8443/api/ingest").unwrap(),
            ("10.0.0.5:8443".into(), "/api/ingest".into())
        );
        assert_eq!(
            split_url("http://central").unwrap(),
            ("central:80".into(), "/api/ingest".into())
        );
        assert!(split_url("https://x").is_err());
    }
}
