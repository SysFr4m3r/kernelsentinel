//! Per-agent ingest keys. Instead of one shared secret for the whole fleet,
//! each host gets its own key, and the key *determines* the host: the server
//! files an incident under the hostname bound to the presenting key, never a
//! self-declared header. So a single leaked key can only write to its own host's
//! bucket -- it cannot impersonate the rest of the fleet.
//!
//! Keys file format, one host per line (blank lines and `#` comments ignored):
//!
//! ```text
//! web-prod-01   b7f3...key
//! db-app-03     9c1a...key
//! ```

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;

/// key -> hostname.
pub struct AgentKeys {
    by_key: HashMap<String, String>,
}

impl AgentKeys {
    pub fn load(path: &str) -> Result<Self, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("reading keys file {path}: {e}"))?;

        // This file is the fleet's ingest credentials in plaintext. World
        // readable means every local account can read every agent key, and a
        // key is all it takes to write incidents as that host -- so the
        // integrity of what the panel shows depends on a file mode nothing
        // checked.
        //
        // Refused rather than warned, on the same test used for enforcement:
        // continuing does active harm, not merely leaving a gap. The fix is one
        // chmod and the message says so, and ssh has refused world-readable
        // private keys for long enough that operators recognise it.
        if let Ok(md) = std::fs::metadata(path) {
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o004 != 0 {
                return Err(format!(
                    "keys file {path} is world-readable (mode {mode:04o}); every local account \
                     can read every agent key. Run: chmod 600 {path}"
                ));
            }
            if mode & 0o040 != 0 {
                eprintln!(
                    "kernelsentinel: warning: keys file {path} is group-readable (mode \
                     {mode:04o}); consider chmod 600"
                );
            }
        }

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
                    // A key repeated across two hosts is a configuration
                    // mistake that cannot be noticed later: the map keeps one
                    // host, and every incident from the other is filed under
                    // the wrong name with nothing to indicate it. Refuse at
                    // load, where the line number is still known.
                    if let Some(first) = by_key.insert(k.to_string(), h.to_string()) {
                        return Err(format!(
                            "keys file {path}:{}: this key is already bound to host {first}; \
                             two hosts sharing a key would file incidents under one name",
                            n + 1
                        ));
                    }
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

    /// Keys files are created 0600, which is both what a real deployment uses
    /// and what `load` now requires.
    fn tempfile() -> (std::fs::File, String) {
        let p = std::env::temp_dir().join(format!("ks-keys-{}.txt", super::generate_key()));
        let path = p.to_str().unwrap().to_string();
        let f = std::fs::File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        (f, path)
    }

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

    /// The file is the fleet's ingest credentials in plaintext. A mode letting
    /// every local account read it compromises every host's telemetry, and
    /// nothing downstream can detect the result afterwards -- an incident
    /// written with a stolen key is indistinguishable from a real one.
    #[test]
    fn a_world_readable_keys_file_is_refused() {
        let mut f = tempfile();
        writeln!(f.0, "web-01 aaaa1111").unwrap();
        std::fs::set_permissions(&f.1, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = match AgentKeys::load(&f.1) {
            Err(e) => e,
            Ok(_) => panic!("a world-readable keys file must be refused"),
        };
        assert!(err.contains("world-readable"), "{err}");
        assert!(
            err.contains("chmod 600"),
            "the fix belongs in the message: {err}"
        );

        // The same file at 0600 loads.
        std::fs::set_permissions(&f.1, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AgentKeys::load(&f.1).is_ok());
    }

    /// Two hosts sharing a key is silent misattribution: the map keeps one host
    /// and the other's incidents are filed under it, with nothing to show for it.
    #[test]
    fn a_duplicate_key_is_refused_with_its_line() {
        let mut f = tempfile();
        writeln!(f.0, "web-01 samekey\ndb-02 samekey").unwrap();
        let err = match AgentKeys::load(&f.1) {
            Err(e) => e,
            Ok(_) => panic!("a duplicate key must be refused"),
        };
        assert!(err.contains(":2:"), "names the offending line: {err}");
        assert!(
            err.contains("web-01"),
            "names the host it collides with: {err}"
        );
    }

    /// One host may legitimately hold several keys, which is how a rotation
    /// happens without a window where the agent cannot ship.
    #[test]
    fn one_host_may_hold_several_keys() {
        let mut f = tempfile();
        writeln!(f.0, "web-01 oldkey\nweb-01 newkey").unwrap();
        let k = AgentKeys::load(&f.1).expect("two keys for one host is legitimate");
        assert_eq!(k.resolve("oldkey"), Some("web-01"));
        assert_eq!(k.resolve("newkey"), Some("web-01"));
        assert_eq!(k.resolve("nokey"), None);
    }
}
