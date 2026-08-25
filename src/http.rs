//! A minimal HTTP/HTTPS POST client.
//!
//! Extracted from the agent's shipping path so alert delivery can reuse it
//! rather than grow a second, subtly different client. Deliberately tiny: this
//! project sends short JSON bodies to a handful of endpoints and has no use for
//! a full HTTP stack.
//!
//! The two TLS modes exist because the two callers trust differently. An agent
//! talking to its own fleet server pins the exact certificate -- the right model
//! for a fixed fleet, where no public CA should be able to forge it. A webhook
//! to a third party (Slack, PagerDuty, a SIEM) has a rotating certificate from a
//! public CA, so it verifies against the system trust store instead.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, Result};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    Http,
    Https,
}

/// How to establish trust for an https endpoint.
pub enum Tls {
    /// Accept only this exact DER certificate.
    Pinned(Vec<u8>),
    /// Verify against the operating system's root store.
    SystemRoots,
}

/// POST `body` to `url` with extra headers. Returns the response status line.
pub fn post(
    url: &str,
    headers: &[(&str, String)],
    content_type: &str,
    body: &str,
    tls: Tls,
) -> Result<String> {
    let (scheme, hostport, path) = split_url(url)?;

    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {hostport}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));

    let mut sock =
        TcpStream::connect(&hostport).with_context(|| format!("connecting to {hostport}"))?;
    // A hung endpoint must not wedge the caller. The alert dispatcher is a
    // background thread, but an unbounded blocking write would still stall
    // every later alert behind it.
    let t = Some(std::time::Duration::from_secs(10));
    let _ = sock.set_read_timeout(t);
    let _ = sock.set_write_timeout(t);

    let resp = match scheme {
        Scheme::Http => {
            sock.write_all(req.as_bytes()).context("sending request")?;
            let mut r = String::new();
            sock.read_to_string(&mut r).ok();
            r
        }
        Scheme::Https => {
            let name = hostport.split(':').next().unwrap_or(&hostport);
            let mut conn = tls_conn(tls, name)?;
            let mut stream = rustls::Stream::new(&mut conn, &mut sock);
            stream.write_all(req.as_bytes()).context("TLS write")?;
            let mut r = String::new();
            let _ = stream.read_to_string(&mut r);
            r
        }
    };
    Ok(resp.lines().next().unwrap_or("").to_string())
}

/// True if a status line reports 2xx.
pub fn is_ok(status: &str) -> bool {
    status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|c| (200..300).contains(&c))
}

fn tls_conn(tls: Tls, server_name: &str) -> Result<rustls::ClientConnection> {
    let builder = rustls::ClientConfig::builder().with_safe_defaults();
    let config = match tls {
        Tls::Pinned(der) => builder
            .with_custom_certificate_verifier(Arc::new(Pinned(der)))
            .with_no_client_auth(),
        Tls::SystemRoots => {
            let mut roots = rustls::RootCertStore::empty();
            let found = rustls_native_certs::load_native_certs()
                .context("loading the system certificate store")?;
            for cert in found {
                // A single unparseable root is not worth failing the whole
                // store over; the rest still verify.
                let _ = roots.add(&rustls::Certificate(cert.0));
            }
            if roots.is_empty() {
                anyhow::bail!("system certificate store is empty; pass a pinned certificate");
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    // With the system store the name is load-bearing (it is checked against the
    // certificate), so a name that will not parse is a hard error rather than
    // something to paper over.
    let name = rustls::ServerName::try_from(server_name)
        .map_err(|_| anyhow::anyhow!("{server_name} is not a valid DNS name for TLS"))?;
    rustls::ClientConnection::new(Arc::new(config), name).context("TLS setup")
}

/// Verifier that accepts the peer iff it presents exactly the pinned cert.
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

/// Read the first certificate out of a PEM file, for pinning.
pub fn load_pinned_cert(path: &str) -> Result<Vec<u8>> {
    let pem = std::fs::read(path).with_context(|| format!("reading pinned cert {path}"))?;
    rustls_pemfile::certs(&mut &pem[..])
        .context("parsing pinned cert")?
        .into_iter()
        .next()
        .context("pinned cert file has no certificate")
}

pub fn split_url(url: &str) -> Result<(Scheme, String, String)> {
    let (scheme, rest, default_port) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r, "443")
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r, "80")
    } else {
        anyhow::bail!("URL must start with http:// or https://");
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    let hostport = if hostport.contains(':') {
        hostport
    } else {
        format!("{hostport}:{default_port}")
    };
    Ok((scheme, hostport, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_splitting() {
        let (s, hp, path) = split_url("http://10.0.0.5:8443/api/ingest").unwrap();
        assert_eq!(s, Scheme::Http);
        assert_eq!(
            (hp.as_str(), path.as_str()),
            ("10.0.0.5:8443", "/api/ingest")
        );
        let (s, hp, path) = split_url("https://central/hooks/x").unwrap();
        assert_eq!(s, Scheme::Https);
        assert_eq!((hp.as_str(), path.as_str()), ("central:443", "/hooks/x"));
        assert!(split_url("ftp://x").is_err());
    }

    #[test]
    fn status_line_classification() {
        assert!(is_ok("HTTP/1.1 200 OK"));
        assert!(is_ok("HTTP/1.1 204 No Content"));
        assert!(!is_ok("HTTP/1.1 404 Not Found"));
        assert!(!is_ok("HTTP/1.1 500 Internal Server Error"));
        assert!(!is_ok(""), "an empty status line is not success");
    }
}
