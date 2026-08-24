//! Stateless, signed session tokens. A token carries the username, role, and an
//! expiry, HMAC-signed with a server secret. The server validates by
//! recomputing the signature -- it holds no per-session state, so sessions
//! survive a restart (the old in-memory session list was wiped on every restart,
//! which logged everyone out).
//!
//! Token format: `hex(payload)"."hex(hmac)` where payload is
//! `username|role|expiry_epoch`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Issue a token valid for `ttl_secs`.
pub fn issue(secret: &[u8], username: &str, role: &str, ttl_secs: u64) -> String {
    let exp = now() + ttl_secs;
    let payload = format!("{username}|{role}|{exp}");
    let sig = sign(secret, payload.as_bytes());
    format!("{}.{}", hex(payload.as_bytes()), sig)
}

/// Validate a token; returns (username, role) if the signature is valid and it
/// has not expired.
pub fn validate(secret: &[u8], token: &str) -> Option<(String, String)> {
    let (payload_hex, sig) = token.split_once('.')?;
    let payload = unhex(payload_hex)?;
    // Constant-time signature check.
    let expected = sign(secret, &payload);
    if !ct_eq(&expected, sig) {
        return None;
    }
    let payload = String::from_utf8(payload).ok()?;
    let mut parts = payload.split('|');
    let username = parts.next()?.to_string();
    let role = parts.next()?.to_string();
    let exp: u64 = parts.next()?.parse().ok()?;
    if now() >= exp {
        return None;
    }
    Some((username, role))
}

fn sign(secret: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(data);
    hex(&mac.finalize().into_bytes())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let secret = b"a-32-byte-server-secret-value!!!";
        let t = issue(secret, "alice", "admin", 3600);
        assert_eq!(validate(secret, &t), Some(("alice".into(), "admin".into())));

        // A different secret rejects it (no forgery without the key).
        assert_eq!(validate(b"different-secret-value-here-0000", &t), None);
        // Tampering the payload (flip a hex nibble) breaks the signature.
        let (ph, sig) = t.split_once('.').unwrap();
        let mut c: Vec<char> = ph.chars().collect();
        c[0] = if c[0] == '0' { '1' } else { '0' };
        let tampered = format!("{}.{}", c.iter().collect::<String>(), sig);
        assert_eq!(validate(secret, &tampered), None);
    }

    #[test]
    fn expiry_enforced() {
        let secret = b"secret";
        let t = issue(secret, "bob", "viewer", 0);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(validate(secret, &t), None);
    }
}
