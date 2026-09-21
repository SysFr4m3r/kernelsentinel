//! What the distribution says should be on this host.
//!
//! Every sweep check asks the same question in a different place: is this file
//! here because a package put it here, or because somebody did? The answer
//! lives in the package manager's own manifests, which is the one authority on
//! a host that an intruder would have to rewrite rather than merely add to.

use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Every path any installed package claims to own.
///
/// Built once and consulted as a set. The obvious implementation -- shelling
/// out to `dpkg -S` per file -- reparses the entire package database on every
/// call and took minutes over a few hundred files. Reading the manifests
/// directly takes 0.27s for 457,641 paths across 3,127 packages on a Kali
/// install, which is the difference between a check somebody runs and one they
/// skip.
pub struct Manifest {
    owned: HashSet<String>,
    /// The manager whose manifests were read, for the report to name. `None`
    /// means no supported manager was found, and every "is this packaged"
    /// answer becomes "unknown" rather than "no" -- see `knows`.
    source: Option<&'static str>,
}

impl Manifest {
    pub fn load() -> Self {
        let mut owned = HashSet::new();
        let mut source = None;

        // Debian and derivatives: one .list per package, one path per line.
        if let Ok(dir) = fs::read_dir("/var/lib/dpkg/info") {
            let mut any = false;
            for entry in dir.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) != Some("list") {
                    continue;
                }
                let Ok(f) = fs::File::open(&p) else { continue };
                for line in BufReader::new(f).lines().map_while(Result::ok) {
                    if !line.is_empty() {
                        owned.insert(line);
                    }
                }
                any = true;
            }
            if any {
                source = Some("dpkg");
            }
        }

        Self { owned, source }
    }

    /// Whether this host has a manifest to compare against at all.
    ///
    /// On a host with no supported package manager every file is unpackaged,
    /// which would turn each check into a listing of the whole filesystem. The
    /// report says so plainly instead: a check that cannot be performed must
    /// not be presented as a check that passed.
    pub fn knows(&self) -> bool {
        self.source.is_some()
    }

    pub fn source(&self) -> &'static str {
        self.source.unwrap_or("none")
    }

    pub fn len(&self) -> usize {
        self.owned.len()
    }

    pub fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }

    /// An empty manifest, for testing the "no authority" path.
    #[cfg(test)]
    pub fn default_for_test() -> Self {
        Self {
            owned: HashSet::new(),
            source: None,
        }
    }

    pub fn owns(&self, path: &Path) -> bool {
        path.to_str().is_some_and(|p| self.owned.contains(p))
    }
}
