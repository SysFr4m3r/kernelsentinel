//! Per-host baselining. The recurring false positive across every milestone has
//! the same shape: a signal fires on a process whose (signal, executable) pair
//! is routine on this host -- privilege_escalation on /usr/bin/sudo, module_load
//! by systemd-modules-load, suid_create by the package manager.
//!
//! A baseline learns those pairs from a known-clean observation period, then the
//! engine downweights a signal whose pair is known-normal while leaving novel
//! behavior at full score. A known pair is *reduced, not erased*, so a routine
//! signal appearing inside a genuinely novel chain still contributes a little.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A signal that fires on a known-normal (signal, exe) pair keeps this fraction
/// of its score. Small but non-zero on purpose.
pub const KNOWN_FACTOR: f64 = 0.1;

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub signal: String,
    pub exe: String,
    pub count: u64,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Baseline {
    pub version: u32,
    #[serde(default)]
    pub events_observed: u64,
    pub entries: Vec<Entry>,

    /// Rebuilt on load from `entries`; not serialized.
    #[serde(skip)]
    index: HashMap<(String, String), u64>,
}

impl Baseline {
    pub fn new() -> Self {
        Self {
            version: 1,
            events_observed: 0,
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Record one observed (signal, exe) pair during learning.
    pub fn observe(&mut self, signal: &str, exe: &str) {
        // An empty exe (unresolved) is not a useful baseline key.
        if exe.is_empty() {
            return;
        }
        *self
            .index
            .entry((signal.to_string(), exe.to_string()))
            .or_insert(0) += 1;
    }

    /// Is this (signal, exe) pair part of the learned-normal set?
    pub fn known(&self, signal: &str, exe: &str) -> bool {
        self.index.contains_key(&(signal.to_string(), exe.to_string()))
    }

    /// Fold the index into the serializable `entries` before saving.
    fn flatten(&mut self) {
        self.entries = self
            .index
            .iter()
            .map(|((signal, exe), count)| Entry {
                signal: signal.clone(),
                exe: exe.clone(),
                count: *count,
            })
            .collect();
        self.entries.sort_by(|a, b| {
            a.signal.cmp(&b.signal).then_with(|| a.exe.cmp(&b.exe))
        });
    }

    /// Rebuild the lookup index after deserializing.
    fn reindex(&mut self) {
        self.index = self
            .entries
            .iter()
            .map(|e| ((e.signal.clone(), e.exe.clone()), e.count))
            .collect();
    }

    pub fn save(&mut self, path: &str) -> std::io::Result<()> {
        self.flatten();
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(path, json)
    }

    pub fn load(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut b: Baseline = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        b.reindex();
        Ok(b)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_after_observed() {
        let mut b = Baseline::new();
        b.observe("privilege_escalation", "/usr/bin/sudo");
        assert!(b.known("privilege_escalation", "/usr/bin/sudo"));
        assert!(!b.known("privilege_escalation", "/tmp/evil"));
        assert!(!b.known("suid_create", "/usr/bin/sudo"));
    }

    #[test]
    fn empty_exe_is_not_learned() {
        let mut b = Baseline::new();
        b.observe("module_load", "");
        assert!(!b.known("module_load", ""));
    }

    #[test]
    fn roundtrips_through_json() {
        let mut b = Baseline::new();
        b.observe("module_load", "/usr/bin/kmod");
        b.observe("module_load", "/usr/bin/kmod");
        let dir = std::env::temp_dir().join("ks-baseline-test.json");
        let path = dir.to_str().unwrap();
        b.save(path).unwrap();
        let loaded = Baseline::load(path).unwrap();
        assert!(loaded.known("module_load", "/usr/bin/kmod"));
    }
}
