//! Agent shipping: read incident NDJSON (from `run --json` or `replay --json`)
//! and POST it to a central fleet server. This is the host->central direction --
//! the only direction. There is deliberately no client that accepts commands
//! from the server.
//!
//! Speaks http:// (localhost/dev) or https:// with a pinned server certificate
//! (--ca). The ingest key travels in a header, so use https for anything beyond
//! localhost.

use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, Result};

/// Read NDJSON incidents from `reader` and POST each batch to `url`
/// (`http://host:port`). `key` authenticates the agent; `host` labels it.
pub fn ship(
    url: &str,
    key: &str,
    host: &str,
    ca: Option<&str>,
    reader: impl BufRead,
) -> Result<()> {
    let (scheme, hostport, path) = split_url(url)?;
    let kernel = read_first_line("/proc/sys/kernel/osrelease");

    let mut sent = 0u64;
    let mut batch = String::new();
    let flush = |batch: &mut String| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        post(scheme, &hostport, &path, key, host, &kernel, ca, batch)?;
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
        // Flush per incident: incidents are infrequent, so ship each promptly
        // rather than buffering (a live `run --json | ship` must not sit silent).
        flush(&mut batch)?;
    }
    flush(&mut batch)?;
    eprintln!("kernelsentinel: shipped {sent} incident(s) to {url}");
    Ok(())
}

#[derive(Clone, Copy)]
enum Scheme {
    Http,
    Https,
}

#[allow(clippy::too_many_arguments)]
fn post(
    scheme: Scheme,
    hostport: &str,
    path: &str,
    key: &str,
    host: &str,
    kernel: &str,
    ca: Option<&str>,
    body: &str,
) -> Result<()> {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nX-Sentinel-Key: {key}\r\n\
         X-Sentinel-Host: {host}\r\nX-Sentinel-Kernel: {kernel}\r\n\
         Content-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut sock =
        TcpStream::connect(hostport).with_context(|| format!("connecting to {hostport}"))?;
    let resp = match scheme {
        Scheme::Http => {
            sock.write_all(req.as_bytes()).context("sending request")?;
            let mut r = String::new();
            sock.read_to_string(&mut r).ok();
            r
        }
        Scheme::Https => {
            let ca = ca.context("https requires --ca <server-cert.pem> to pin the server")?;
            let name = hostport.split(':').next().unwrap_or(hostport);
            let mut conn = tls_conn(ca, name)?;
            let mut stream = rustls::Stream::new(&mut conn, &mut sock);
            stream.write_all(req.as_bytes()).context("TLS write")?;
            let mut r = String::new();
            let _ = stream.read_to_string(&mut r);
            r
        }
    };
    let status = resp.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        anyhow::bail!("server rejected the batch: {status}");
    }
    Ok(())
}

/// A rustls client that trusts ONLY the exact pinned certificate in `ca`. This
/// is true certificate pinning -- the right trust model for a fixed fleet: the
/// server must present exactly this cert, so no public CA (or a rogue one) can
/// forge it. Identity is the cert, not the hostname.
fn tls_conn(ca: &str, server_name: &str) -> Result<rustls::ClientConnection> {
    let pem = std::fs::read(ca).with_context(|| format!("reading pinned cert {ca}"))?;
    let der = rustls_pemfile::certs(&mut &pem[..])
        .context("parsing pinned cert")?
        .into_iter()
        .next()
        .context("pinned cert file has no certificate")?;

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(Pinned(der)))
        .with_no_client_auth();
    // The pin makes the SNI name irrelevant to trust; use it only for the handshake.
    let name = rustls::ServerName::try_from(server_name)
        .unwrap_or_else(|_| rustls::ServerName::try_from("localhost").unwrap());
    rustls::ClientConnection::new(Arc::new(config), name).context("TLS setup")
}

/// Verifier that accepts the server iff it presents exactly the pinned cert.
struct Pinned(Vec<u8>);
impl rustls::client::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        if end_entity.0 == self.0 {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned cert".into(),
            ))
        }
    }
}

fn split_url(url: &str) -> Result<(Scheme, String, String)> {
    let (scheme, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r, "443")
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r, "80")
    } else {
        anyhow::bail!("ship URL must start with http:// or https://");
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/api/ingest".to_string()),
    };
    let hostport = if hostport.contains(':') {
        hostport
    } else {
        format!("{hostport}:{default_port}")
    };
    Ok((scheme, hostport, path))
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
        let (_, hp, path) = split_url("http://10.0.0.5:8443/api/ingest").unwrap();
        assert_eq!(
            (hp.as_str(), path.as_str()),
            ("10.0.0.5:8443", "/api/ingest")
        );
        let (_, hp, path) = split_url("https://central/api/ingest").unwrap();
        assert_eq!((hp.as_str(), path.as_str()), ("central:443", "/api/ingest"));
        assert!(split_url("ftp://x").is_err());
    }
}
