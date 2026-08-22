//! The set of paths the file_open sensor watches. Populated into the BPF
//! LPM-trie at startup so matching happens in-kernel; userspace never sees the
//! firehose of unrelated opens.

use std::fs;

/// Mirror of `WATCH_ON_WRITE` in bpf/events.h.
pub const WATCH_ON_WRITE: u32 = 1 << 0;

pub const MAX_WATCH_PATH: usize = 256;

/// One watch: an absolute path *prefix* and the flags gating a match. Because
/// the trie does longest-prefix matching, a trailing slash makes an entry a
/// directory watch ("/etc/cron.d/" catches every file beneath it) while no
/// trailing slash matches that exact file and anything sharing its byte prefix.
pub struct Watch {
    pub prefix: String,
    pub flags: u32,
}

impl Watch {
    fn write(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            flags: WATCH_ON_WRITE,
        }
    }
}

/// A short human label for a matched watch, for display and (later) detections.
/// Keyed on prefix so it survives the flags being extended.
pub fn label_for(path: &str) -> &'static str {
    const RULES: &[(&str, &str)] = &[
        ("/etc/ld.so.preload", "ld.so.preload (linker hijack)"),
        ("/.ssh/authorized_keys", "authorized_keys"),
        ("/root/.ssh/", "root SSH keys"),
        ("/etc/cron", "cron"),
        ("/etc/systemd/", "systemd unit"),
        ("/usr/lib/systemd/", "systemd unit"),
        ("/lib/systemd/", "systemd unit"),
        ("/etc/sudoers", "sudoers"),
        ("/etc/shadow", "shadow"),
        ("/etc/passwd", "passwd"),
    ];
    RULES
        .iter()
        .find(|(needle, _)| path.contains(needle))
        .map(|(_, label)| *label)
        .unwrap_or("watched path")
}

/// The default watch set. Static high-value write targets plus a dynamic sweep
/// of every user's SSH directory, since authorized_keys lives at a per-user
/// path a single prefix cannot cover.
pub fn default_watches() -> Vec<Watch> {
    let mut w = vec![
        Watch::write("/etc/ld.so.preload"),
        Watch::write("/etc/cron"),        // crontab, cron.d/, cron.daily/, ...
        Watch::write("/etc/systemd/"),
        Watch::write("/usr/lib/systemd/"),
        Watch::write("/lib/systemd/"),
        Watch::write("/etc/sudoers"),     // sudoers and sudoers.d/
        Watch::write("/etc/shadow"),
        Watch::write("/etc/passwd"),
        Watch::write("/root/.ssh/"),
    ];

    // Per-user SSH directories. A missing /home is fine (containers, minimal
    // hosts); this is best-effort enrichment, not a hard dependency.
    if let Ok(entries) = fs::read_dir("/home") {
        for home in entries.flatten() {
            let ssh = home.path().join(".ssh/");
            if let Some(p) = ssh.to_str() {
                w.push(Watch::write(p));
            }
        }
    }
    w
}

/// Encode a watch as the raw `struct path_key` bytes the BPF map expects:
/// `u32 prefixlen` (native endian) followed by `char path[256]`.
pub fn encode_key(prefix: &str) -> Option<[u8; 4 + MAX_WATCH_PATH]> {
    let bytes = prefix.as_bytes();
    if bytes.len() >= MAX_WATCH_PATH {
        return None;
    }
    let mut key = [0u8; 4 + MAX_WATCH_PATH];
    // Exclude any trailing NUL from the match, mirroring the kernel side which
    // computes prefixlen from the path length without its terminator.
    let prefixlen = (bytes.len() as u32) * 8;
    key[..4].copy_from_slice(&prefixlen.to_ne_bytes());
    key[4..4 + bytes.len()].copy_from_slice(bytes);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_key_layout_matches_bpf_struct() {
        let key = encode_key("/etc/").unwrap();
        // prefixlen is native-endian u32 in the first 4 bytes: 5 chars * 8 bits.
        let prefixlen = u32::from_ne_bytes(key[..4].try_into().unwrap());
        assert_eq!(prefixlen, 40, "prefixlen must be bit count of the path");
        // path bytes follow, exactly the prefix, no NUL counted in the length.
        assert_eq!(&key[4..9], b"/etc/");
        assert_eq!(key[9], 0, "remainder must be zero-padded");
        assert_eq!(key.len(), 4 + MAX_WATCH_PATH);
    }

    #[test]
    fn encode_key_rejects_overlong_prefix() {
        let long = "/".repeat(MAX_WATCH_PATH);
        assert!(encode_key(&long).is_none(), "must not overflow the key buffer");
    }

    #[test]
    fn encode_key_at_boundary() {
        // One below the buffer is allowed; exactly the buffer size is not.
        let ok = "a".repeat(MAX_WATCH_PATH - 1);
        let bad = "a".repeat(MAX_WATCH_PATH);
        assert!(encode_key(&ok).is_some());
        assert!(encode_key(&bad).is_none());
    }

    #[test]
    fn label_matches_on_substring() {
        assert_eq!(label_for("/etc/cron.d/evil"), "cron");
        assert_eq!(label_for("/home/kali/.ssh/authorized_keys"), "authorized_keys");
        assert_eq!(label_for("/etc/ld.so.preload"), "ld.so.preload (linker hijack)");
    }

    #[test]
    fn default_watches_all_encodable() {
        for w in default_watches() {
            assert!(encode_key(&w.prefix).is_some(), "unencodable: {}", w.prefix);
        }
    }
}
