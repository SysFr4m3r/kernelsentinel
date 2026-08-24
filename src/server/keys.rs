//! Per-agent ingest keys. Instead of one shared secret for the whole fleet,
//! each host gets its own key, and the key *determines* the host: the server
//! files an incident under the hostname bound to the presenting key, never a
//! self-declared header. So a single leaked key can only write to its own host's
//! bucket -- it cannot impersonate the rest of the fleet.
//!
//! Keys file format, one host per line (blank lines and `#` comments ignored):
//!
//!     web-prod-01   b7f3...key
//!     db-app-03     9c1a...key

use std::collections::HashMap;

/// key -> hostname.
pub struct AgentKeys {
    by_key: HashMap<String, String>,
}

impl AgentKeys {
    pub fn load(path: &str) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("reading keys file {path}: {e}"))?;
        let mut by_key = HashMap::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let host = it.next();
            let key = it.next();
            match (host, key) {
                (Some(h), Some(k)) if !k.is_empty() => {
                    by_key.insert(k.to_string(), h.to_string());
                }
                _ => return Err(format!("keys file {path}:{}: expected `host key`", n + 1)),
            }
        }
        if by_key.is_empty() {
            return Err(format!("keys file {path} has no entries"));
        }
        Ok(Self { by_key })
    }

    /// Resolve a presented key to its bound hostname, constant-time across all
    /// candidates so a valid key cannot be distinguished by timing.
    pub fn resolve(&self, presented: &str) -> Option<&str> {
        let mut found: Option<&str> = None;
        for (key, host) in &self.by_key {
            if super::ct_eq(key, presented) {
                found = Some(host);
            }
        }
        found
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Generate a fresh 32-byte agent key as hex.
pub fn generate_key() -> String {
    super::random_token()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn key_binds_to_host() {
        let mut f = tempfile();
        writeln!(f.0, "# fleet keys\nweb-01  aaaa1111\ndb-02   bbbb2222\n").unwrap();
        let keys = AgentKeys::load(&f.1).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.resolve("aaaa1111"), Some("web-01"));
        assert_eq!(keys.resolve("bbbb2222"), Some("db-02"));
        // A wrong/unknown key resolves to nothing -- cannot write anywhere.
        assert_eq!(keys.resolve("cccc3333"), None);
    }

    #[test]
    fn malformed_line_is_rejected() {
        let mut f = tempfile();
        writeln!(f.0, "onlyhost").unwrap();
        assert!(AgentKeys::load(&f.1).is_err());
    }

    fn tempfile() -> (std::fs::File, String) {
        let p = std::env::temp_dir().join(format!("ks-keys-{}.txt", super::generate_key()));
        let path = p.to_str().unwrap().to_string();
        (std::fs::File::create(&path).unwrap(), path)
    }
}
