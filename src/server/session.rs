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
    // Exactly three fields, or the token is not one this server issued the way
    // it thinks it did.
    //
    // The payload is `username|role|expiry`, and the username is chosen by
    // whoever asked for the account. A username of `mallory|admin|99999999999`
    // produces a payload with five fields, and taking the first three of those
    // reads the *username's* second field as the role and its third as the
    // expiry -- so an account issued as `viewer` for eight hours validated as
    // `admin` until the year 5138, using a signature the server itself made.
    //
    // Usernames are now restricted at creation so this cannot be stored, but a
    // database predating that restriction may already hold one, and a signature
    // check cannot notice: the token is genuine. Counting the fields can.
    let parts: Vec<&str> = payload.split('|').collect();
    let [username, role, exp] = parts.as_slice() else {
        return None;
    };
    let (username, role) = (username.to_string(), role.to_string());
    let exp: u64 = exp.parse().ok()?;
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

    /// A username cannot smuggle a role or an expiry through the delimiter.
    ///
    /// The payload is `username|role|expiry`. Issued for `viewer` with an
    /// eight-hour life, an account named `mallory|admin|99999999999` used to
    /// validate as `admin` until the year 5138 -- on a signature the server had
    /// genuinely produced, so nothing about the token was forged.
    #[test]
    fn a_username_cannot_smuggle_a_role_through_the_delimiter() {
        let secret = b"server-secret";
        let token = super::issue(secret, "mallory|admin|99999999999", "viewer", 60);
        assert_eq!(
            super::validate(secret, &token),
            None,
            "a payload with more than three fields is not a token this server can read"
        );

        // The ordinary case still works.
        let good = super::issue(secret, "mallory", "viewer", 60);
        assert_eq!(
            super::validate(secret, &good),
            Some(("mallory".into(), "viewer".into()))
        );

        // And a truncated payload is refused rather than half-read.
        let short = super::issue(secret, "mallory", "viewer", 60);
        let short = &short[..short.find('.').unwrap()];
        assert_eq!(super::validate(secret, short), None);
    }
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
