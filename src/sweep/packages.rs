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

        // Arch and derivatives. One directory per installed package, each with
        // a `files` manifest: a `%FILES%` header followed by paths relative to
        // the root, with directories written with a trailing slash.
        if source.is_none() {
            if let Ok(dir) = fs::read_dir("/var/lib/pacman/local") {
                let mut any = false;
                for entry in dir.flatten() {
                    let Ok(f) = fs::File::open(entry.path().join("files")) else {
                        continue;
                    };
                    let mut in_files = false;
                    for line in BufReader::new(f).lines().map_while(Result::ok) {
                        if line.starts_with('%') {
                            // Sections other than %FILES% list backup paths and
                            // checksums, which are not the question here.
                            in_files = line.trim() == "%FILES%";
                            continue;
                        }
                        if !in_files || line.is_empty() || line.ends_with('/') {
                            continue;
                        }
                        owned.insert(format!("/{line}"));
                    }
                    any = true;
                }
                if any {
                    source = Some("pacman");
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A pacman `files` manifest, parsed the way `load` parses it. Split out
    /// because the development host is Debian and the target is Arch, and a
    /// format nobody can test on the machine they are writing on is a format
    /// that gets guessed at.
    fn parse_pacman(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut in_files = false;
        for line in text.lines() {
            if line.starts_with('%') {
                in_files = line.trim() == "%FILES%";
                continue;
            }
            if !in_files || line.is_empty() || line.ends_with('/') {
                continue;
            }
            out.push(format!("/{line}"));
        }
        out
    }

    #[test]
    fn a_pacman_manifest_yields_absolute_file_paths() {
        let files = parse_pacman(
            "%FILES%\n\
             usr/\n\
             usr/bin/\n\
             usr/bin/sudo\n\
             usr/lib/sudo/sudoers.so\n\
             \n\
             %BACKUP%\n\
             etc/sudoers\t9a8b7c\n",
        );
        // Paths are relative in the file and absolute everywhere else.
        assert_eq!(files, vec!["/usr/bin/sudo", "/usr/lib/sudo/sudoers.so"]);
        // Directories carry a trailing slash and are not files.
        assert!(!files.iter().any(|f| f.ends_with('/')));
        // %BACKUP% lists checksums, not ownership, and must not leak in as a
        // path -- it would arrive with a tab and a hash attached.
        assert!(!files.iter().any(|f| f.contains('\t')));
    }

    /// A host with no supported manager must say so rather than reporting that
    /// every file on it is unpackaged.
    #[test]
    fn no_manager_is_unknown_not_empty() {
        let m = Manifest {
            owned: HashSet::new(),
            source: None,
        };
        assert!(!m.knows());
        assert_eq!(m.source(), "none");
    }
}
